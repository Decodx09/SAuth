#!/usr/bin/env node

const OAuthClientManager = require('../utils/oauthClientManager');
require('dotenv').config();

const commands = {
  register: async (args) => {
    const name = args[0];
    const redirectUris = args[1] ? args[1].split(',') : [];
    const scopes = args[2] || 'read';

    if (!name || !redirectUris.length) {
      console.error('Usage: node manage-oauth-clients.js register "App Name" "http://localhost:3001/callback,https://app.com/callback" "read write"');
      process.exit(1);
    }

    try {
      const client = await OAuthClientManager.registerClient({
        name,
        redirectUris,
        scopes
      });

      console.log('\n✅ OAuth Client Registered Successfully!');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`Client ID:     ${client.clientId}`);
      console.log(`Client Secret: ${client.clientSecret}`);
      console.log(`Name:          ${client.name}`);
      console.log(`Redirect URIs: ${client.redirectUris}`);
      console.log(`Scopes:        ${client.scopes}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('\n⚠️  Store the Client Secret securely - it won\'t be shown again!');
    } catch (error) {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  },

  list: async () => {
    try {
      const clients = await OAuthClientManager.listClients();
      
      if (clients.length === 0) {
        console.log('No OAuth clients found.');
        return;
      }

      console.log('\n📋 OAuth Clients');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      
      clients.forEach((client, index) => {
        console.log(`${index + 1}. ${client.name}`);
        console.log(`   Client ID: ${client.client_id}`);
        console.log(`   Redirect URIs: ${client.redirect_uris.join(', ')}`);
        console.log(`   Scopes: ${client.scope}`);
        console.log(`   Status: ${client.is_active ? '✅ Active' : '❌ Inactive'}`);
        console.log(`   Created: ${client.created_at}`);
        console.log('');
      });
    } catch (error) {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  },

  get: async (args) => {
    const clientId = args[0];
    
    if (!clientId) {
      console.error('Usage: node manage-oauth-clients.js get <client_id>');
      process.exit(1);
    }

    try {
      const client = await OAuthClientManager.getClient(clientId);
      
      if (!client) {
        console.log('❌ Client not found');
        return;
      }

      console.log('\n📋 OAuth Client Details');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`Name:          ${client.name}`);
      console.log(`Client ID:     ${client.client_id}`);
      console.log(`Redirect URIs: ${client.redirect_uris.join(', ')}`);
      console.log(`Scopes:        ${client.scope}`);
      console.log(`Status:        ${client.is_active ? '✅ Active' : '❌ Inactive'}`);
      console.log(`Created:       ${client.created_at}`);
      console.log(`Updated:       ${client.updated_at}`);
    } catch (error) {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  },

  deactivate: async (args) => {
    const clientId = args[0];
    
    if (!clientId) {
      console.error('Usage: node manage-oauth-clients.js deactivate <client_id>');
      process.exit(1);
    }

    try {
      const success = await OAuthClientManager.deactivateClient(clientId);
      
      if (success) {
        console.log('✅ Client deactivated successfully');
      } else {
        console.log('❌ Client not found');
      }
    } catch (error) {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  },

  'regenerate-secret': async (args) => {
    const clientId = args[0];
    
    if (!clientId) {
      console.error('Usage: node manage-oauth-clients.js regenerate-secret <client_id>');
      process.exit(1);
    }

    try {
      const newSecret = await OAuthClientManager.regenerateSecret(clientId);
      
      console.log('\n✅ Client Secret Regenerated!');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`Client ID:     ${clientId}`);
      console.log(`New Secret:    ${newSecret}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('\n⚠️  Update your application with the new secret!');
    } catch (error) {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  }
};

const showHelp = () => {
  console.log(`
🔐 OAuth Client Manager

Usage: node manage-oauth-clients.js <command> [args]

Commands:
  register <name> <redirect_uris> [scopes]  Register a new OAuth client
  list                                      List all OAuth clients  
  get <client_id>                          Get client details
  deactivate <client_id>                   Deactivate a client
  regenerate-secret <client_id>            Regenerate client secret

Examples:
  node manage-oauth-clients.js register "My App" "http://localhost:3001/callback"
  node manage-oauth-clients.js register "My App" "http://localhost:3001/callback,https://myapp.com/callback" "read write profile"
  node manage-oauth-clients.js list
  node manage-oauth-clients.js get abc123def456
  node manage-oauth-clients.js deactivate abc123def456
  node manage-oauth-clients.js regenerate-secret abc123def456
`);
};

// Main execution
const main = async () => {
  const [,, command, ...args] = process.argv;

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    showHelp();
    return;
  }

  if (!commands[command]) {
    console.error(`❌ Unknown command: ${command}`);
    showHelp();
    process.exit(1);
  }

  await commands[command](args);
  process.exit(0);
};

main().catch(error => {
  console.error('❌ Unexpected error:', error);
  process.exit(1);
});