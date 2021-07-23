# OPSWAT_API_Assignment

Problem Description:Generate a simple program to scan a file against our  API. OPSWAT online help contains details of our publicly metadefender.opswat.comavailable API along with sample code that shows how to scan a file. However, it is costly to multi-scan a file so we would like you to implement a hash lookup prior to deciding to upload a file, either way you should retrieve results and display them. Please read through the documentation and sample code found at https://onlinehelp.opswat.com/mdcloud/3._Public_APIs.html to perform the following logic.

1. Calculate the hash of the given samplefile.txtNo samplefile is provided, you may use any files you choose up to 140Mb.  
                a. No samplefile is provided, you may use any files you choose up to 140Mb.  
2. Perform a hash lookup against metadefender.opswat.com and see if there are previously cached results for the file.    
3. If results found then skip to 6.  
4. If results not found then upload the file, receive a data_id.  
5. Repeatedly poll on the data_id to retrieve results.  
6. Display results in format below  
You should also have some basic error handling for common HTTP results, but its not necessary to account for every idiosyncrasy of our API. You can show any errors to the standard error and exit the application.   

# Run Program

- Install python 3  
- cd into OPSWAT  
- Put test file in OPSWAT directory  

# Enter command:  
- python3 scan_file.py -f "INSERT FILE HERE" -k "INSERT YOUR APIKEY"  
- ex: python3 solution.py -f test.txt -k a166c3fb8be911b1d46179711037789e  


