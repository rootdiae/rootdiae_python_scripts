import pandas as pd

# Load the Excel file (make sure 'your_file.xlsx' is the correct path)
df = pd.read_excel("repo_lists.xlsx")  

# Get the header names from the DataFrame
headers = df.columns.tolist()

# Combine data from the columns and keep track of original columns
all_values = []
for col_index in range(len(headers)):
    # Access column by its header name
    current_column = headers[col_index]  
    all_values.append(df[current_column].to_frame(name='Value').assign(Source=current_column))
combined_df = pd.concat(all_values, ignore_index=True)

# Calculate value counts
value_counts = combined_df['Value'].value_counts()

# Create a list to store column headers for each value
source_columns = []
for value in value_counts.index:
    source_columns.append(', '.join(combined_df[combined_df['Value'] == value]['Source'].unique()))

# Create the output DataFrame
output_df = pd.DataFrame({
    'Value': value_counts.index,
    'Count': value_counts.values,
    'Source Columns': source_columns
})

# Save to Excel
output_df.to_excel("value_counts_with_sources.xlsx", index=False)