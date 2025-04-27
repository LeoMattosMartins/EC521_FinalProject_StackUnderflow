// Function to filter the JSON data
function filterJSON(jsonData) {
    // Array to store our filtered results
    const filteredResults = [];
    
    // Loop through each question object in the array
    jsonData.forEach(question => {
      // For each answer in the question
      question.answers.forEach(answer => {
        // Create a new object with just url and body
        filteredResults.push({
          url: question.url,
          body: answer.body
        });
      });
    });
    
    return filteredResults;
  }
  
  // Node.js file system module
  const fs = require('fs');
  
  // Get command line arguments for input and output files
  // Default to input.json and output.json if not provided
  const inputFile = process.argv[2] || 'input.json';
  const outputFile = process.argv[3] || 'output.json';
  
  try {
    // Read the input file
    console.log(`Reading from ${inputFile}...`);
    const rawData = fs.readFileSync(inputFile, 'utf8');
    
    // Parse the JSON data
    const inputData = JSON.parse(rawData);
    
    // Process the data
    const filteredData = filterJSON(inputData);
    
    // Convert to JSON string with pretty formatting
    const outputJSON = JSON.stringify(filteredData, null, 2);
    
    // Save to output file
    console.log(`Writing to ${outputFile}...`);
    fs.writeFileSync(outputFile, outputJSON);
    
    console.log(`Successfully processed ${inputData.length} questions with ${filteredData.length} answers.`);
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }