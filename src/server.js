#!/usr/bin/env node

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import chalk from 'chalk';
import { getConfig } from './commands/init.js';
import { initDb, all, get, exec } from './utils/database.js';
import { logAudit } from './utils/audit.js';
import { encrypt, decrypt, setMasterKey } from './utils/crypto.js';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Auth middleware (simplified)
function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // Simplified - in production, use proper JWT
  req.user = { id: 'api-user', username: 'api' };
  next();
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// List environments
app.get('/api/environments', authenticate, async (req, res) => {
  try {
    await initDb();
    const environments = all('SELECT * FROM environments ORDER BY name');
    res.json(environments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create environment
app.post('/api/environments', authenticate, async (req, res) => {
  try {
    await initDb();
    const { name, description } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const id = uuidv4();
    exec('INSERT INTO environments (id, name, description) VALUES (?, ?, ?)', [id, name, description || '']);
    
    logAudit({
      action: 'create',
      entityType: 'environment',
      entityId: id,
      newValue: JSON.stringify({ name, description }),
      userId: req.user.id,
      userName: req.user.username
    });
    
    res.status(201).json({ id, name, description });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// List variables
app.get('/api/environments/:env/variables', authenticate, async (req, res) => {
  try {
    await initDb();
    const { env } = req.params;
    
    const envData = get('SELECT * FROM environments WHERE name = ?', [env]);
    if (!envData) {
      return res.status(404).json({ error: 'Environment not found' });
    }
    
    const variables = all('SELECT * FROM variables WHERE environment_id = ?', [envData.id]);
    res.json(variables);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get variable
app.get('/api/environments/:env/variables/:key', authenticate, async (req, res) => {
  try {
    await initDb();
    const { env, key } = req.params;
    
    const envData = get('SELECT * FROM environments WHERE name = ?', [env]);
    if (!envData) {
      return res.status(404).json({ error: 'Environment not found' });
    }
    
    const variable = get('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [envData.id, key]);
    if (!variable) {
      return res.status(404).json({ error: 'Variable not found' });
    }
    
    // Return decrypted if secret
    let value = variable.value;
    if (variable.is_secret && req.query.decrypt === 'true') {
      try {
        value = decrypt(variable.value);
      } catch (e) {
        return res.status(403).json({ error: 'Failed to decrypt' });
      }
    }
    
    res.json({ ...variable, value });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Set variable
app.post('/api/environments/:env/variables', authenticate, async (req, res) => {
  try {
    await initDb();
    const { env } = req.params;
    const { key, value, is_secret, tags, description } = req.body;
    
    if (!key || value === undefined) {
      return res.status(400).json({ error: 'Key and value are required' });
    }
    
    const envData = get('SELECT * FROM environments WHERE name = ?', [env]);
    if (!envData) {
      return res.status(404).json({ error: 'Environment not found' });
    }
    
    let storedValue = value;
    let isEncrypted = 0;
    
    if (is_secret) {
      storedValue = encrypt(value);
      isEncrypted = 1;
    }
    
    const existing = get('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [envData.id, key]);
    const id = existing?.id || uuidv4();
    
    if (existing) {
      exec(
        `UPDATE variables SET value = ?, encrypted = ?, is_secret = ?, tags = ?, description = ?, updated_at = datetime('now') WHERE id = ?`,
        [storedValue, isEncrypted, is_secret ? 1 : 0, tags || '', description || '', id]
      );
    } else {
      exec(
        `INSERT INTO variables (id, environment_id, key, value, encrypted, is_secret, tags, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, envData.id, key, storedValue, isEncrypted, is_secret ? 1 : 0, tags || '', description || '']
      );
    }
    
    logAudit({
      action: existing ? 'update' : 'create',
      entityType: 'variable',
      entityId: id,
      newValue: is_secret ? '[SECRET]' : storedValue,
      userId: req.user.id,
      userName: req.user.username
    });
    
    res.status(201).json({ id, key, is_secret });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete variable
app.delete('/api/environments/:env/variables/:key', authenticate, async (req, res) => {
  try {
    await initDb();
    const { env, key } = req.params;
    
    const envData = get('SELECT * FROM environments WHERE name = ?', [env]);
    if (!envData) {
      return res.status(404).json({ error: 'Environment not found' });
    }
    
    const variable = get('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [envData.id, key]);
    if (!variable) {
      return res.status(404).json({ error: 'Variable not found' });
    }
    
    exec('DELETE FROM variables WHERE id = ?', [variable.id]);
    
    logAudit({
      action: 'delete',
      entityType: 'variable',
      entityId: variable.id,
      oldValue: variable.value,
      userId: req.user.id,
      userName: req.user.username
    });
    
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get audit logs
app.get('/api/audit', authenticate, async (req, res) => {
  try {
    await initDb();
    const { action, entity_type, limit = 50 } = req.query;
    
    let sql = 'SELECT * FROM audit_logs WHERE 1=1';
    const params = [];
    
    if (action) {
      sql += ' AND action = ?';
      params.push(action);
    }
    if (entity_type) {
      sql += ' AND entity_type = ?';
      params.push(entity_type);
    }
    
    sql += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(parseInt(limit));
    
    const logs = all(sql, params);
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
async function startServer() {
  const config = getConfig();
  if (!config) {
    console.log(chalk.red('✗ Not initialized. Run CLI first: ') + chalk.cyan('envguard init'));
    process.exit(1);
  }
  
  await initDb();
  
  app.listen(PORT, () => {
    console.log(chalk.cyan(`🚀 EnvGuard API server running on port ${PORT}`));
    console.log(chalk.gray(`  Health: http://localhost:${PORT}/health`));
    console.log(chalk.gray(`  API: http://localhost:${PORT}/api`));
  });
}

startServer().catch(console.error);
