
from pathlib import Path
import pandas as pd

# Project directories
PROJECT_DIR = Path(__file__).resolve().parent

RAW_DATASET = (
    Path.home()
    / "Downloads"
    / "meajor_cleaned_preprocessed.parquet.gzip"
)

OUTPUT_DIR = PROJECT_DIR / "data" / "processed"
OUTPUT_FILE = OUTPUT_DIR / "meajor_cleaned.parquet"


def prepare_dataset():

    print("Loading MeAJOR dataset...")

    df = pd.read_parquet(RAW_DATASET)

    print("Original records:", len(df))

    # Check required columns
    required_columns = ["label", "body"]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(f"Missing required column: {column}")

    # Remove exact duplicate records
    clean_df = df.drop_duplicates().copy()

    # Remove records without labels or message bodies
    clean_df = clean_df.dropna(
        subset=["label", "body"]
    ).copy()

    # Remove empty or whitespace-only message bodies
    clean_df = clean_df[
        clean_df["body"].str.strip() != ""
    ].copy()

    # Validate labels
    if not clean_df["label"].isin([0, 1]).all():
        raise ValueError("Unexpected label values found.")

    # Save processed dataset
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    clean_df.to_parquet(
        OUTPUT_FILE,
        index=False
    )

    print("\nDataset preparation completed!")
    print("Original records:", len(df))
    print("Cleaned records:", len(clean_df))
    print("\nLabel distribution:")
    print(clean_df["label"].value_counts())
    print("\nSaved to:", OUTPUT_FILE)


if __name__ == "__main__":
    prepare_dataset()
