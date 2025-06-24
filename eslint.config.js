// eslint.config.js

// Import the necessary packages
import globals from "globals";
import js from "@eslint/js";

// Export the configuration array
export default [
  // This applies the recommended default rules from ESLint
  js.configs.recommended,

  {
    languageOptions: {
      ecmaVersion: 2022, // Use a modern ECMAScript version
      sourceType: "module", // Assumes you are using ES Modules (import/export)
      
      // This defines the global variables available in your environment
      globals: {
        ...globals.node, // Add all Node.js global variables
      },
    },
    
    // Add any custom rules you want to enforce or override
    rules: {
      "semi": ["error", "always"],
      "quotes": ["error", "double"]
      // Example: "no-unused-vars": "warn"
    },
    
    // This configuration applies to all .js and .mjs files
  }
];
