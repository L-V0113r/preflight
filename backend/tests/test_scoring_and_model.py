import unittest

import numpy as np

from preflight.config import ScoringSettings
from preflight.data import SyntheticWebFactory
from preflight.features import FEATURE_NAMES
from preflight.ml import train_model
from preflight.ml.dataset import featurise
from preflight.schema import Finding, Severity, Verdict
from preflight.scoring import decide, noisy_or
from tests.helpers import INTEL

SETTINGS = ScoringSettings()


def finding(severity: Severity) -> Finding:
    return Finding("t", "t", "t", severity, "test")


class NoisyOrTests(unittest.TestCase):
    def test_bounds_and_monotonic(self):
        self.assertEqual(noisy_or([]), 0.0)
        self.assertAlmostEqual(noisy_or([0.5, 0.5]), 0.75)
        self.assertLessEqual(noisy_or([0.9] * 50), 1.0)
        self.assertGreater(noisy_or([0.2, 0.3]), noisy_or([0.2]))


class DecideTests(unittest.TestCase):
    def test_critical_finding_is_always_danger(self):
        out = decide([finding(Severity.CRITICAL)], 0.0, content_analysed=True,
                     out_of_distribution=False, settings=SETTINGS)
        self.assertEqual(out.verdict, Verdict.DANGER)

    def test_clean_page_is_safe(self):
        out = decide([], 0.02, content_analysed=True, out_of_distribution=False, settings=SETTINGS)
        self.assertEqual(out.verdict, Verdict.SAFE)

    def test_strict_failed_fetch_is_always_unsure(self):
        for p in (0.01, 0.99):
            out = decide([], p, content_analysed=False, out_of_distribution=False,
                         settings=SETTINGS, mode="full", profile=SETTINGS.strict)
            self.assertEqual(out.verdict, Verdict.UNSURE, p)

    def test_balanced_failed_fetch_with_clean_link_opens(self):
        out = decide([], 0.01, content_analysed=False, out_of_distribution=False,
                     settings=SETTINGS, mode="full", profile=SETTINGS.balanced)
        self.assertEqual(out.verdict, Verdict.SAFE)
        self.assertTrue(any("only the link" in n for n in out.notes))

    def test_balanced_failed_fetch_with_suspicious_link_asks(self):
        out = decide([], 0.5, content_analysed=False, out_of_distribution=False,
                     settings=SETTINGS, mode="full", profile=SETTINGS.balanced)
        self.assertEqual(out.verdict, Verdict.UNSURE)
        out = decide([finding(Severity.LOW)], 0.01, content_analysed=False,
                     out_of_distribution=False, settings=SETTINGS, mode="full",
                     profile=SETTINGS.balanced)
        self.assertEqual(out.verdict, Verdict.UNSURE)

    def test_failed_fetch_with_concrete_rule_can_still_warn(self):
        for profile in (SETTINGS.balanced, SETTINGS.strict):
            out = decide([finding(Severity.HIGH)], 0.9, content_analysed=False,
                         out_of_distribution=False, settings=SETTINGS, mode="full",
                         profile=profile)
            self.assertIn(out.verdict, (Verdict.CAUTION, Verdict.DANGER))

    def test_strict_unfamiliar_page_is_unsure(self):
        out = decide([], 0.05, content_analysed=True, out_of_distribution=True,
                     settings=SETTINGS, profile=SETTINGS.strict)
        self.assertEqual(out.verdict, Verdict.UNSURE)

    def test_balanced_unfamiliar_page_needs_a_reason(self):
        out = decide([], 0.05, content_analysed=True, out_of_distribution=True,
                     settings=SETTINGS, profile=SETTINGS.balanced)
        self.assertEqual(out.verdict, Verdict.SAFE)
        out = decide([finding(Severity.LOW)], 0.05, content_analysed=True,
                     out_of_distribution=True, settings=SETTINGS, profile=SETTINGS.balanced)
        self.assertEqual(out.verdict, Verdict.UNSURE)

    def test_undecided_model_always_asks(self):
        for profile in (SETTINGS.balanced, SETTINGS.strict):
            out = decide([], 0.4, content_analysed=True, out_of_distribution=False,
                         settings=SETTINGS, profile=profile)
            self.assertEqual(out.verdict, Verdict.UNSURE)


class BaseRateTests(unittest.TestCase):
    """The prior-shift maths in RiskModel.adjust_for_base_rate."""

    @staticmethod
    def model_with_rate(malicious, total):
        from preflight.ml.model import ModelBundle, RiskModel
        bundle = ModelBundle(estimator=None, feature_names=FEATURE_NAMES,
                             reference=np.zeros(len(FEATURE_NAMES)),
                             low=np.zeros(len(FEATURE_NAMES)), high=np.ones(len(FEATURE_NAMES)),
                             metadata={"n_samples": total, "n_malicious": malicious})
        return RiskModel(bundle)

    def test_same_rate_changes_nothing(self):
        model = self.model_with_rate(40, 100)
        self.assertAlmostEqual(model.adjust_for_base_rate(0.7, 0.40), 0.7, places=6)

    def test_rarer_attacks_lower_the_probability(self):
        model = self.model_with_rate(40, 100)
        # odds 1 at a 40% training rate -> odds (0.1/0.9)/(0.4/0.6) = 1/6 at 10%
        self.assertAlmostEqual(model.adjust_for_base_rate(0.5, 0.10), 1 / 7, places=6)
        self.assertLess(model.adjust_for_base_rate(0.9, 0.10), 0.9)

    def test_order_is_preserved(self):
        model = self.model_with_rate(40, 100)
        ps = [0.1, 0.3, 0.5, 0.8, 0.99]
        adjusted = [model.adjust_for_base_rate(p, 0.05) for p in ps]
        self.assertEqual(adjusted, sorted(adjusted))

    def test_unknown_rate_leaves_probability_unchanged(self):
        model = self.model_with_rate(40, 100)
        self.assertEqual(model.adjust_for_base_rate(0.7, None), 0.7)


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        samples = SyntheticWebFactory(seed=3).generate(300, 200)
        data = featurise(samples, INTEL.protected_domains)
        cls.data = data
        cls.model, cls.report = train_model(data.X, data.y, seed=3, data_description="test")

    def test_features_have_fixed_shape(self):
        self.assertEqual(self.data.X.shape[1], len(FEATURE_NAMES))
        self.assertFalse(np.isnan(self.data.X).any())

    def test_model_separates_classes_on_training_data(self):
        probs = self.model.predict_many(self.data.X)
        self.assertGreater(probs[self.data.y == 1].mean(), 0.7)
        self.assertLess(probs[self.data.y == 0].mean(), 0.3)

    def test_explanations_name_real_features(self):
        bad_row = self.data.X[np.argmax(self.model.predict_many(self.data.X))]
        for factor in self.model.explain(bad_row):
            self.assertIn(factor.feature, FEATURE_NAMES)
            self.assertGreater(factor.contribution, 0)

    def test_out_of_range_values_are_noticed(self):
        weird = self.data.X[0].copy() + 1e6
        self.assertGreater(len(self.model.unusual_features(weird)), 10)


if __name__ == "__main__":
    unittest.main()
