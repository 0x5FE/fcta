- The FCTA is in active development and may have bugs.

- Report bugs and suggestions for improvements to the GitHub repository.

- FCTA is an open source project and is available ***for use and community contribution.***

- It is important to test and evaluate the tool before putting it into production.

# Install the dependencies:

    Pip install -r requirements.txt
    
# Configure cloud provider credentials:

- Create a config.ini file in the root folder of the project.

- Enter access keys and other authentication details ***for AWS, Google Cloud, and Azure.***

# Run the tool:

    python fcta.py

# Possible Errors and Solutions:

- ***Authentication Error:*** Verify that the cloud provider credentials are configured correctly.
- ***Library import error:*** Install the missing library using Pip install.
- ***Data format error:*** Verify that the security data is in the correct format.

# Future Improvements:

- [ ] Integration with other security data sources.
- [ ] Implementation of more advanced anomaly detection algorithms.
- [ ] Improved user interface for ease of use.
- [ ] Generation of automated reports
