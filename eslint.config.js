// eslint.config.js

// This file now uses the CommonJS module system (require/module.exports)
// to match your project's default setup.

const globals = require("globals");
const js = require("@eslint/js");

module.exports = [
  // This applies the recommended default rules from ESLint
  js.configs.recommended,

  // --- Main Configuration for all .js files ---
  {
    files: ["**/*.js", "**/*.mjs"], // Apply this to all JavaScript files
    languageOptions: {
      ecmaVersion: 2022, // Use a modern ECMAScript version
      sourceType: "module", // Your code *within* files uses ES Modules
      
      // This defines the global variables available in your environment
      globals: {
        ...globals.node, // Add all Node.js global variables
      },
    },
    
    // Custom rules for your entire project
    rules: {
      "semi": ["error", "always"],
      "quotes": ["error", "single"], 
      "no-unused-vars": "warn", 
    },
  },

  // --- Test File Specific Configuration ---
  {
    files: ["tests/**/*.js"], // ONLY apply this to files in the 'tests' directory
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest, // Add globals for the Jest testing framework
      }
    },
    rules: {
      // You can add rules specific to tests here if needed
    }
  },
];
