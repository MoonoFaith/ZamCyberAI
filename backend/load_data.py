import csv
import os

DATA_DIR = "bigc-data" # Your folder inside backend

def load_tsv(filepath):
    """Load TSV file and return list of (english, bemba) pairs."""
    pairs = []
    with open(filepath, encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        header = next(reader) # Skip header row
        print(f"Columns found: {header[:8]}...") # Show first 8 columns to confirm

        for row in reader:
            if len(row) >= 7: # Need at least 7 columns
                bemba = row[5].strip() # Column 6 = 'sentence' = Bemba
                english = row[6].strip() # Column 7 = 'translation' = English

                if bemba and english: # Skip empty rows
                    pairs.append((english, bemba))
    return pairs

def test_file(name, filepath):
    """Run basic tests on a dataset file."""
    print(f"\n{'='*60}")
    print(f"Testing: {name}")
    print(f"{'='*60}")

    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return

    pairs = load_tsv(filepath)
    print(f"✅ File loaded successfully")
    print(f"📊 Total sentence pairs: {len(pairs)}")

    print(f"\n📝 First 5 examples:")
    print(f"{'ENGLISH':<45} | {'BEMBA'}")
    print(f"{'-'*45}-+-{'-'*45}")
    for eng, bem in pairs[:5]:
        print(f"{eng[:43]:<45} | {bem[:43]}")

# Run tests
if __name__ == "__main__":
    test_file("train.tsv", os.path.join(DATA_DIR, "train.tsv"))
    test_file("valid.tsv", os.path.join(DATA_DIR, "valid.tsv"))
    test_file("test.tsv", os.path.join(DATA_DIR, "test.tsv"))