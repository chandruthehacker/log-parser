import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Visualize the frequency of log entries by status code
def generate_visualization(parsed_logs):
    df = pd.DataFrame(parsed_logs)
    sns.set_theme(style="darkgrid")
    
    # Plot frequency of each HTTP status code
    plt.figure(figsize=(10, 6))
    sns.countplot(x='status', data=df)
    plt.title("Frequency of HTTP Status Codes")
    plt.xlabel("HTTP Status Code")
    plt.ylabel("Count")
    plt.show()
