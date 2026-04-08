import pandas as pd

def filter_data(file1, file2):
    # Read the first CSV file
    df1 = pd.read_csv(file1)
    
    # Read the second CSV file
    df2 = pd.read_csv(file2)
    
    # if global_company of file1 is in file2 global_company, keep it
    filtered_df1 = df1[df1['global_company'].isin(df2['global_company'])]
    return filtered_df1

filtered=filter_data("global2000_gh_profiles_2000.csv", "MAIN_global2000_complete.csv")
filtered.to_csv("global2000_gh_profiles.csv", index=False)
