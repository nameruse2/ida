import csv

def load_input(value):
    if value.endswith(".txt"):
        with open(value, mode="r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return [value]

def write_to_csv(dict_list: dict, filename: str):
    """
    Output the extracted information to a CSV file.
    Args:
        dict_list (list): List of dictionaries containing extracted information
        filename (str): The name of the output CSV file
    Returns:
        dict: Extracted information in a structured format
    """
    if not dict_list:
        print("The list is empty. No CSV file created.")
        return

    # Get the fieldnames from the keys of the first dictionary
    fieldnames = dict_list[0].keys()

    try:
        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(dict_list)
        print(f"CSV file '{filename}' written successfully.")
    except Exception as e:
        print(f"Error writing CSV file: {e}")
