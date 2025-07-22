const crypto = require('crypto');
const { pool } = require('../config/database');

class OAuthClientManager {
  /**
   * Register a new OAuth client application
   */
  static async registerClient(clientData) {
    const {
      name,
      redirectUris, // Array of redirect URIs
      scopes = 'read'
    } = clientData;

    // Generate client credentials
    const clientId = crypto.randomBytes(16).toString('hex');
    const clientSecret = crypto.randomBytes(32).toString('hex');
    
    // Join redirect URIs with comma
    const redirectUriString = Array.isArray(redirectUris) 
      ? redirectUris.join(',') 
      : redirectUris;

    try {
      await pool.execute(
        `INSERT INTO oauth_clients 
         (client_id, client_secret, name, redirect_uri, scope) 
         VALUES (?, ?, ?, ?, ?)`,
        [clientId, clientSecret, name, redirectUriString, scopes]
      );

      return {
        clientId,
        clientSecret,
        name,
        redirectUris: redirectUriString,
        scopes
      };
    } catch (error) {
      throw new Error(`Failed to register client: ${error.message}`);
    }
  }

  /**
   * Get client by ID
   */
  static async getClient(clientId) {
    try {
      const [clients] = await pool.execute(
        'SELECT * FROM oauth_clients WHERE client_id = ? AND is_active = 1',
        [clientId]
      );

      if (!clients.length) {
        return null;
      }

      const client = clients[0];
      return {
        ...client,
        redirect_uris: client.redirect_uri.split(',').map(uri => uri.trim())
      };
    } catch (error) {
      throw new Error(`Failed to get client: ${error.message}`);
    }
  }

  /**
   * List all clients
   */
  static async listClients() {
    try {
      const [clients] = await pool.execute(
        'SELECT client_id, name, redirect_uri, scope, is_active, created_at FROM oauth_clients ORDER BY created_at DESC'
      );

      return clients.map(client => ({
        ...client,
        redirect_uris: client.redirect_uri.split(',').map(uri => uri.trim())
      }));
    } catch (error) {
      throw new Error(`Failed to list clients: ${error.message}`);
    }
  }

  /**
   * Update client
   */
  static async updateClient(clientId, updates) {
    const allowedUpdates = ['name', 'redirect_uri', 'scope', 'is_active'];
    const updateFields = [];
    const updateValues = [];

    Object.keys(updates).forEach(key => {
      if (allowedUpdates.includes(key)) {
        updateFields.push(`${key} = ?`);
        updateValues.push(updates[key]);
      }
    });

    if (updateFields.length === 0) {
      throw new Error('No valid fields to update');
    }

    updateValues.push(clientId);

    try {
      const [result] = await pool.execute(
        `UPDATE oauth_clients SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE client_id = ?`,
        updateValues
      );

      return result.affectedRows > 0;
    } catch (error) {
      throw new Error(`Failed to update client: ${error.message}`);
    }
  }

  /**
   * Delete/Deactivate client
   */
  static async deactivateClient(clientId) {
    try {
      const [result] = await pool.execute(
        'UPDATE oauth_clients SET is_active = 0 WHERE client_id = ?',
        [clientId]
      );

      return result.affectedRows > 0;
    } catch (error) {
      throw new Error(`Failed to deactivate client: ${error.message}`);
    }
  }

  /**
   * Regenerate client secret
   */
  static async regenerateSecret(clientId) {
    const newSecret = crypto.randomBytes(32).toString('hex');

    try {
      const [result] = await pool.execute(
        'UPDATE oauth_clients SET client_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE client_id = ?',
        [newSecret, clientId]
      );

      if (result.affectedRows === 0) {
        throw new Error('Client not found');
      }

      return newSecret;
    } catch (error) {
      throw new Error(`Failed to regenerate secret: ${error.message}`);
    }
  }
}

module.exports = OAuthClientManager;