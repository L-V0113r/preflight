"""Training data: labelled synthetic pages and loaders for real datasets."""

from preflight.data.loaders import load_html_folder, load_url_csv
from preflight.data.synthetic import LabelledPage, SyntheticWebFactory

__all__ = ["LabelledPage", "SyntheticWebFactory", "load_html_folder", "load_url_csv"]
