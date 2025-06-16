#!/bin/bash

# This script sends 100 user registration requests to the local server.

echo "Starting to send 100 registration requests..."

for i in {1..100}
do
   # The loop variable 'i' is used to make the email unique for each request.
   # Example emails will be: shivanshsukhija+test1@gmail.com, shivanshsukhija+test2@gmail.com, etc.
   
   echo "Sending request #$i..."
   
   curl -X POST http://localhost:3000/api/auth/register \
   -H "Content-Type: application/json" \
   -d '{
       "firstName": "shivansh",
       "lastName": "sukhija",
       "email": "shivanshsukhija+test'"${i}"'@gmail.com",
       "password": "Wordlikeme1!",
       "confirmPassword": "Wordlikeme1!",
       "role": "user"
   }'
   
   # This will print the server's response for each request.
   # Add a newline for better readability between responses.
   echo "" 
   
   # Optional: Add a small delay of 0.1 seconds to not overwhelm the server
   sleep 0.1
done

echo "Finished sending all 100 requests."