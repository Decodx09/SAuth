// eslint.config.js

// This file now uses the CommonJS module system (require/module.exports)
// and is configured to match your project's coding style.

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
      // Switched this back to "double" to match your code and fix errors.
      "quotes": ["error", "double"], 
      // Semicolons are good practice.
      "semi": ["error", "always"],
      // Unused variables will now only be a warning, not a build-breaking error.
      "no-unused-vars": "warn",
      // Disabled the rule for useless escapes, which can be overly strict with regex.
      "no-useless-escape": "off",
    },
  },

  // --- Test File Specific Configuration ---
  {
    files: ["tests/**/*.js"], // ONLY apply this to files in the 'tests' directory
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest, // Add globals for the Jest testing framework (describe, it, expect, etc.)
      }
    },
    rules: {
      // Rules specific to tests can go here
    }
  },
];
