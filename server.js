const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');

const app = express();
const PORT = process.env.PORT || 5000;

// Google Drive Configuration
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
const REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN;

// Optional: Create a specific folder for assignments
const ASSIGNMENT_FOLDER_NAME = process.env.ASSIGNMENT_FOLDER_NAME;

const oauth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
oauth2Client.setCredentials({ refresh_token: REFRESH_TOKEN });

const drive = google.drive({
    version: 'v3',  
    auth: oauth2Client,
});

// Function to get or create assignment folder
async function getAssignmentFolder() {
  try {
    // Search for existing folder
    const response = await drive.files.list({
      q: `name='${ASSIGNMENT_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
      fields: 'files(id, name)',
    });

    if (response.data.files.length > 0) {
      return response.data.files[0].id;
    }

    // Create new folder if it doesn't exist
    const folderMetadata = {
      name: ASSIGNMENT_FOLDER_NAME,
      mimeType: 'application/vnd.google-apps.folder',
    };

    const folder = await drive.files.create({
      requestBody: folderMetadata,
      fields: 'id',
    });

    console.log(`📁 Created assignment folder: ${folder.data.id}`);
    return folder.data.id;
  } catch (error) {
    console.error('❌ Error creating/getting folder:', error);
    return null; // Fall back to root upload
  }
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow common document and image types
    const allowedTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'text/plain',
      'image/jpeg',
      'image/png',
      'image/gif'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only documents and images are allowed.'), false);
    }
  }
});

// Middleware
const allowedOrigins = [
  'https://ecareners-frontend.vercel.app',
  'https://ecareners.com',
  'https://www.ecareners.com',
  'http://localhost:5173'
  // Add more domains as needed
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(express.json());

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
};

// Create connection pool
const pool = mysql.createPool(dbConfig);

// Test database connection
pool.getConnection()
  .then(connection => {
    console.log('✅ Database connected successfully');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
  });

// SOP Routes
app.get('/api/sops', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT sop_id, title, url, category FROM sop ORDER BY sop_id ASC');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching SOPs:', error);
    res.status(500).json({ error: 'Failed to fetch SOPs' });
  }
});

app.get('/api/sops/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT sop_id, title, url, category FROM sop WHERE sop_id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'SOP not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching SOP:', error);
    res.status(500).json({ error: 'Failed to fetch SOP' });
  }
});

app.post('/api/sops', async (req, res) => {
  try {
    const { title, url, category = '' } = req.body;
    const [result] = await pool.query('INSERT INTO sop (title, url, category) VALUES (?, ?, ?)', [title, url, category]);
    res.status(201).json({ id: result.insertId, title, url, category });
  } catch (error) {
    console.error('Error creating SOP:', error);
    res.status(500).json({ error: 'Failed to create SOP' });
  }
});

app.put('/api/sops/:id', async (req, res) => {
  try {
    const { title, url, category = '' } = req.body;
    const [result] = await pool.query('UPDATE sop SET title = ?, url = ?, category = ? WHERE sop_id = ?', [title, url, category, req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'SOP not found' });
    }
    res.json({ id: req.params.id, title, url, category });
  } catch (error) {
    console.error('Error updating SOP:', error);
    res.status(500).json({ error: 'Failed to update SOP' });
  }
});

app.delete('/api/sops/:id', async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM sop WHERE sop_id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'SOP not found' });
    }
    res.json({ message: 'SOP deleted successfully' });
  } catch (error) {
    console.error('Error deleting SOP:', error);
    res.status(500).json({ error: 'Failed to delete SOP' });
  }
});

// Video Routes
app.get('/api/videos', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT videos_id, title, url, category FROM videos ORDER BY videos_id ASC');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching videos:', error);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT videos_id, title, url, category FROM videos WHERE videos_id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching video:', error);
    res.status(500).json({ error: 'Failed to fetch video' });
  }
});

app.post('/api/videos', async (req, res) => {
  try {
    const { title, url, category = '' } = req.body;
    const [result] = await pool.query('INSERT INTO videos (title, url, category) VALUES (?, ?, ?)', [title, url, category]);
    res.status(201).json({ id: result.insertId, title, url, category });
  } catch (error) {
    console.error('Error creating video:', error);
    res.status(500).json({ error: 'Failed to create video' });
  }
});

app.put('/api/videos/:id', async (req, res) => {
  try {
    const { title, url, category = '' } = req.body;
    const [result] = await pool.query('UPDATE videos SET title = ?, url = ?, category = ? WHERE videos_id = ?', [title, url, category, req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    res.json({ id: req.params.id, title, url, category });
  } catch (error) {
    console.error('Error updating video:', error);
    res.status(500).json({ error: 'Failed to update video' });
  }
});

app.delete('/api/videos/:id', async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM videos WHERE videos_id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    res.json({ message: 'Video deleted successfully' });
  } catch (error) {
    console.error('Error deleting video:', error);
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// Register endpoint
app.post('/api/register', async (req, res) => {
  const { name, email, password, role, prodi } = req.body;
  if (!name || !email || !password || !role || !prodi) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  try {
    // Check if user already exists
    const [existing] = await pool.query('SELECT user_id FROM user WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ message: 'Email already registered.' });
    }
    // Generate new user_id (U00001, U00002, ...)
    const [rows] = await pool.query("SELECT user_id FROM user ORDER BY user_id DESC LIMIT 1");
    let newIdNum = 1;
    if (rows.length > 0) {
      const lastId = rows[0].user_id;
      newIdNum = parseInt(lastId.substring(1)) + 1;
    }
    const user_id = 'U' + newIdNum.toString().padStart(5, '0');
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Insert user
    await pool.query(
      'INSERT INTO user (user_id, name, email, password, role, prodi) VALUES (?, ?, ?, ?, ?, ?)',
      [user_id, name, email, hashedPassword, role, prodi]
    );
    res.status(201).json({ message: 'Registration successful.' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Registration failed.' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }
  try {
    // Find user by email
    const [users] = await pool.query('SELECT * FROM user WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    const user = users[0];
    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    // Create JWT token
    const token = jwt.sign(
      { user_id: user.user_id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '30m' }
    );
    // Return user info (excluding password) and token
    const { password: _, ...userInfo } = user;
    res.json({ message: 'Login successful.', user: userInfo, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed.' });
  }
});

// JWT authentication middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key', (err, user) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid or expired token.' });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ message: 'Authorization header missing.' });
  }
}

// Example: Assessment route with role-based access
app.get('/api/clinical-assessments', authenticateJWT, (req, res) => {
  // Only allow users whose role is not 'mahasiswa'
  if (req.user.role === 'mahasiswa') {
    return res.status(403).json({ message: 'Access denied: Mahasiswa cannot access assessment.' });
  }
  // ... fetch and return assessments ...
  res.json({ message: 'Assessment data (placeholder)' });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'API is running' });
});

// Test database and tables
app.get('/api/test/database', async (req, res) => {
  try {
    console.log('🔍 Testing database connection and tables...');
    
    // Test connection
    const connection = await pool.getConnection();
    console.log('✅ Database connection successful');
    
    // Test tables
    const tables = ['user', 'assignments', 'submission', 'assessments'];
    const results = {};
    
    for (const table of tables) {
      try {
        const [rows] = await connection.execute(`SELECT COUNT(*) as count FROM ${table}`);
        results[table] = { exists: true, count: rows[0].count };
        console.log(`✅ Table ${table}: ${rows[0].count} records`);
      } catch (err) {
        results[table] = { exists: false, error: err.message };
        console.log(`❌ Table ${table}: ${err.message}`);
      }
    }
    
    // Test user roles
    try {
      const [roles] = await connection.execute(`
        SELECT role, COUNT(*) as count 
        FROM user 
        GROUP BY role
      `);
      results.userRoles = roles;
      console.log('✅ User roles:', roles);
    } catch (err) {
      results.userRoles = { error: err.message };
      console.log(`❌ Error getting user roles: ${err.message}`);
    }
    
    // Test specific mahasiswa query
    try {
      const [mahasiswaCount] = await connection.execute(`
        SELECT COUNT(*) as count 
        FROM user 
        WHERE role = 'mahasiswa'
      `);
      results.mahasiswaCount = mahasiswaCount[0].count;
      console.log(`✅ Mahasiswa count: ${mahasiswaCount[0].count}`);
    } catch (err) {
      results.mahasiswaCount = { error: err.message };
      console.log(`❌ Error getting mahasiswa count: ${err.message}`);
    }
    
    // Test user table structure
    try {
      const [columns] = await connection.execute(`
        DESCRIBE user
      `);
      results.userTableStructure = columns;
      console.log('✅ User table structure:', columns);
    } catch (err) {
      results.userTableStructure = { error: err.message };
      console.log(`❌ Error getting user table structure: ${err.message}`);
    }
    
    connection.release();
    res.json({ 
      status: 'OK', 
      message: 'Database test completed',
      results 
    });
  } catch (err) {
    console.error('❌ Database test failed:', err);
    res.status(500).json({ 
      status: 'ERROR', 
      message: 'Database test failed',
      error: err.message 
    });
  }
});

// Database test endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    console.log('🔍 Testing database connection and tables...');
    
    // Test connection
    const connection = await pool.getConnection();
    console.log('✅ Database connection successful');
    
    // Test tables
    const tables = ['user', 'assignments', 'submission', 'assessments'];
    const results = {};
    
    for (const table of tables) {
      try {
        const [rows] = await connection.execute(`SELECT COUNT(*) as count FROM ${table}`);
        results[table] = { exists: true, count: rows[0].count };
        console.log(`✅ Table ${table}: ${rows[0].count} records`);
      } catch (err) {
        results[table] = { exists: false, error: err.message };
        console.log(`❌ Table ${table}: ${err.message}`);
      }
    }
    
    connection.release();
    res.json({ 
      status: 'OK', 
      message: 'Database test completed',
      results 
    });
  } catch (err) {
    console.error('❌ Database test failed:', err);
    res.status(500).json({ 
      status: 'ERROR', 
      message: 'Database test failed',
      error: err.message 
    });
  }
});

// Get all assignments
app.get('/api/assignments', async (req, res) => {
  try {
    console.log('📚 Fetching all assignments...');
    const [rows] = await pool.query('SELECT * FROM assignments ORDER BY due_date ASC');
    console.log(`✅ Found ${rows.length} assignments`);
    res.json(rows);
  } catch (err) {
    console.error('❌ Error fetching assignments:', err);
    console.error('❌ Error details:', err.message);
    console.error('❌ Error stack:', err.stack);
    res.status(500).json({ message: 'Failed to fetch assignments.' });
  }
});

// Get all submissions
app.get('/api/submissions', async (req, res) => {
  const { user_id } = req.query;
  if (!user_id) return res.status(400).json({ message: 'user_id is required' });
  try {
    const [rows] = await pool.query('SELECT * FROM submission WHERE user_id = ?', [user_id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch submissions', error: err.message });
  }
});

// Get submission by user and assignment
app.get('/api/submissions/:userId/:assignmentId', async (req, res) => {
  try {
    const { userId, assignmentId } = req.params;
    console.log(`🔍 Fetching submission for user ${userId}, assignment ${assignmentId}`);
    
    const [rows] = await pool.query(`
      SELECT s.*, a.title as assignment_title
      FROM submission s
      JOIN assignments a ON s.assignment_id = a.assignment_id
      WHERE s.user_id = ? AND s.assignment_id = ?
    `, [userId, assignmentId]);
    
    console.log(`📊 Found ${rows.length} submissions`);
    
    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: 'Submission not found.' });
    }
  } catch (err) {
    console.error('Error fetching submission:', err);
    res.status(500).json({ message: 'Failed to fetch submission.' });
  }
});

// Get submissions by assignment_id
app.get('/api/assignments/:assignmentId/submissions', async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const [rows] = await pool.query(`
      SELECT s.*, u.name as user_name, u.email
      FROM submission s
      JOIN user u ON s.user_id = u.user_id
      WHERE s.assignment_id = ?
      ORDER BY s.submitted_at DESC
    `, [assignmentId]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching submissions:', err);
    res.status(500).json({ message: 'Failed to fetch submissions.' });
  }
});

// Submit assignment
app.post('/api/assignments/:assignmentId/submit', async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const { user_id, google_drive_file_id, text } = req.body;
    
    if (!user_id || !google_drive_file_id || !text) {
      return res.status(400).json({ message: 'user_id, google_drive_file_id, and text are required.' });
    }
    
    // Check if assignment exists
    const [assignmentRows] = await pool.query('SELECT * FROM assignments WHERE assignment_id = ?', [assignmentId]);
    if (assignmentRows.length === 0) {
      return res.status(404).json({ message: 'Assignment not found.' });
    }
    
    // Check if user exists
    const [userRows] = await pool.query('SELECT * FROM user WHERE user_id = ?', [user_id]);
    if (userRows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    
    // Check if submission already exists
    const [existingSubmission] = await pool.query(
      'SELECT * FROM submission WHERE user_id = ? AND assignment_id = ?',
      [user_id, assignmentId]
    );
    
    if (existingSubmission.length > 0) {
      // Update existing submission
      await pool.query(
        'UPDATE submission SET google_drive_file_id = ?, text = ?, submitted_at = NOW() WHERE user_id = ? AND assignment_id = ?',
        [google_drive_file_id, text, user_id, assignmentId]
      );
      res.json({ message: 'Submission updated successfully.' });
    } else {
      // Create new submission
      await pool.query(
        'INSERT INTO submission (user_id, assignment_id, google_drive_file_id, text, submitted_at) VALUES (?, ?, ?, ?, NOW())',
        [user_id, assignmentId, google_drive_file_id, text]
      );
      res.status(201).json({ message: 'Submission created successfully.' });
    }
  } catch (err) {
    console.error('Error submitting assignment:', err);
    res.status(500).json({ message: 'Failed to submit assignment.' });
  }
});

// Upload file to Google Drive
app.post('/api/upload-to-drive', upload.single('file'), async (req, res) => {
  try {
    console.log('📁 File upload request received');
    
    if (!req.file) {
      console.log('❌ No file uploaded');
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    const fileName = req.file.originalname;
    const mimeType = req.file.mimetype;

    console.log(`📤 Uploading file: ${fileName} (${mimeType}) to Google Drive...`);
    console.log(`📂 File path: ${filePath}`);

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      console.log('❌ File does not exist at path:', filePath);
      return res.status(500).json({ error: 'File not found on server' });
    }

    // Get assignment folder (optional)
    let folderId = null;
    try {
      folderId = await getAssignmentFolder();
      if (folderId) {
        console.log(`📁 Using folder: ${folderId}`);
      }
    } catch (folderError) {
      console.log('⚠️ Could not get folder, uploading to root');
    }

    // Upload to Google Drive
    const uploadBody = {
      name: fileName,
      mimeType: mimeType,
    };

    // Add folder if available
    if (folderId) {
      uploadBody.parents = [folderId];
    }

    const response = await drive.files.create({
      requestBody: uploadBody,
      media: {
        mimeType: mimeType,
        body: fs.createReadStream(filePath),
      }
    });

    // Make the uploaded file public
    await drive.permissions.create({
      fileId: response.data.id,
      requestBody: {
        role: 'reader',
        type: 'anyone',
      },
    });

    // Get the public URL of the file
    const fileMeta = await drive.files.get({
      fileId: response.data.id,
      fields: 'webViewLink, webContentLink',
    });

    // Clean up temporary file
    fs.unlinkSync(filePath);

    console.log(`✅ File uploaded successfully. File ID: ${response.data.id}`);

    res.json({ 
      success: true,
      fileId: response.data.id,
      fileName: fileName,
      webViewLink: fileMeta.data.webViewLink,
      webContentLink: fileMeta.data.webContentLink,
      message: 'File uploaded to Google Drive and made public successfully'
    });

  } catch (error) {
    console.error('❌ Error uploading file to Google Drive:', error);
    console.error('❌ Error details:', error.message);
    console.error('❌ Error stack:', error.stack);
    
    // Clean up temporary file if it exists
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('🧹 Cleaned up temporary file');
      } catch (cleanupError) {
        console.error('❌ Error cleaning up file:', cleanupError);
      }
    }

    res.status(500).json({ 
      error: 'Failed to upload file to Google Drive',
      details: error.message 
    });
  }
});

// Error handling middleware for multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
    }
    return res.status(400).json({ error: 'File upload error: ' + error.message });
  }
  
  if (error.message.includes('Invalid file type')) {
    return res.status(400).json({ error: error.message });
  }
  
  next(error);
});

// Assessment Routes
app.get('/api/assessments', async (req, res) => {
  try {
    const { 
      assessment_type, 
      academic_year, 
      semester, 
      assessor_id, 
      assessed_id,
      limit = 50,
      offset = 0
    } = req.query;
    
    console.log('🔍 Fetching assessments with filters:', {
      assessment_type,
      academic_year,
      semester,
      assessor_id,
      assessed_id,
      limit,
      offset
    });
    
    let query = `
      SELECT a.*, 
             u1.name as assessed_user_name,
             u2.name as assessor_user_name,
             s.google_drive_file_id,
             s.text as submission_text,
             ass.title as assignment_title
      FROM assessments a
      JOIN user u1 ON a.assessed_user_id = u1.user_id
      JOIN user u2 ON a.assessor_user_id = u2.user_id
      LEFT JOIN submission s ON a.submission_id = s.submission_id
      LEFT JOIN assignments ass ON s.assignment_id = ass.assignment_id
      WHERE 1=1
    `;
    
    const queryParams = [];
    
    // Add filters
    if (assessment_type) {
      query += ' AND a.assessment_type = ?';
      queryParams.push(assessment_type);
    }
    
    if (academic_year) {
      query += ' AND a.academic_year = ?';
      queryParams.push(academic_year);
    }
    
    if (semester) {
      query += ' AND a.semester = ?';
      queryParams.push(semester);
    }
    
    if (assessor_id) {
      query += ' AND a.assessor_user_id = ?';
      queryParams.push(assessor_id);
    }
    
    if (assessed_id) {
      query += ' AND a.assessed_user_id = ?';
      queryParams.push(assessed_id);
    }
    
    // Add ordering and pagination
    query += ' ORDER BY a.assessment_date DESC LIMIT ? OFFSET ?';
    queryParams.push(parseInt(limit), parseInt(offset));
    
    const [rows] = await pool.query(query, queryParams);
    console.log(`✅ Found ${rows.length} assessments`);
    
    res.json(rows);
  } catch (err) {
    console.error('❌ Error fetching assessments:', err);
    console.error('❌ Error details:', err.message);
    res.status(500).json({ message: 'Failed to fetch assessments.' });
  }
});

// Get assessments by assignment
app.get('/api/assignments/:assignmentId/assessments', async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const [rows] = await pool.query(`
      SELECT a.*, 
             u1.name as assessed_user_name,
             u2.name as assessor_user_name,
             s.google_drive_file_id,
             s.text as submission_text,
             ass.title as assignment_title
      FROM assessments a
      JOIN user u1 ON a.assessed_user_id = u1.user_id
      JOIN user u2 ON a.assessor_user_id = u2.user_id
      LEFT JOIN submission s ON a.submission_id = s.submission_id
      LEFT JOIN assignments ass ON s.assignment_id = ass.assignment_id
      WHERE s.assignment_id = ?
      ORDER BY a.assessment_date DESC
    `, [assignmentId]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching assessments:', err);
    res.status(500).json({ message: 'Failed to fetch assessments.' });
  }
});

// Get students and their submissions for an assignment
app.get('/api/assignments/:assignmentId/students', async (req, res) => {
  try {
    const { assignmentId } = req.params;
    console.log(`🔍 Fetching students for assignment: ${assignmentId}`);
    
    // First, test database connection
    const connection = await pool.getConnection();
    console.log('✅ Database connection successful');
    
    // Test if user table exists and has data
    try {
      const [userCount] = await connection.execute('SELECT COUNT(*) as count FROM user');
      console.log(`📊 User table has ${userCount[0].count} records`);
    } catch (userError) {
      console.error('❌ Error accessing user table:', userError.message);
      return res.status(500).json({ 
        message: 'Database table error', 
        error: 'User table not accessible',
        details: userError.message 
      });
    }
    
    // Test if submission table exists
    try {
      const [submissionCount] = await connection.execute('SELECT COUNT(*) as count FROM submission');
      console.log(`📊 Submission table has ${submissionCount[0].count} records`);
    } catch (submissionError) {
      console.error('❌ Error accessing submission table:', submissionError.message);
      return res.status(500).json({ 
        message: 'Database table error', 
        error: 'Submission table not accessible',
        details: submissionError.message 
      });
    }
    
    // Test if assessments table exists
    try {
      const [assessmentCount] = await connection.execute('SELECT COUNT(*) as count FROM assessments');
      console.log(`📊 Assessments table has ${assessmentCount[0].count} records`);
    } catch (assessmentError) {
      console.error('❌ Error accessing assessments table:', assessmentError.message);
      return res.status(500).json({ 
        message: 'Database table error', 
        error: 'Assessments table not accessible',
        details: assessmentError.message 
      });
    }
    
    connection.release();
    
    // Get all students with better error handling
    console.log('📚 Fetching all students...');
    let students = [];
    try {
      // First, let's check what roles exist in the database
      const [roleCheck] = await pool.query(`
        SELECT DISTINCT role, COUNT(*) as count
      FROM user 
        GROUP BY role
      `);
      console.log('🔍 Available roles in database:', roleCheck);
      
      // Now fetch students with mahasiswa role
      const [studentRows] = await pool.query(`
        SELECT user_id, name, email, prodi, role
        FROM user 
        WHERE role = 'mahasiswa'
      ORDER BY name
    `);
      students = studentRows;
      console.log(`✅ Found ${students.length} students with role 'mahasiswa'`);
    } catch (studentError) {
      console.error('❌ Error fetching students:', studentError.message);
      return res.status(500).json({ 
        message: 'Failed to fetch students', 
        error: studentError.message 
      });
    }
    
    // Get submissions for this assignment with better error handling
    console.log(`📝 Fetching submissions for assignment ${assignmentId}...`);
    let submissions = [];
    try {
      const [submissionRows] = await pool.query(`
      SELECT s.*, u.name as user_name, u.email, u.prodi
      FROM submission s
      JOIN user u ON s.user_id = u.user_id
      WHERE s.assignment_id = ?
      ORDER BY s.submitted_at DESC
    `, [assignmentId]);
      submissions = submissionRows;
    console.log(`✅ Found ${submissions.length} submissions`);
    } catch (submissionError) {
      console.error('❌ Error fetching submissions:', submissionError.message);
      // Don't return error, just continue with empty submissions
      submissions = [];
    }
    
    // Get assessments for this assignment with better error handling
    console.log(`⭐ Fetching assessments for assignment ${assignmentId}...`);
    let assessments = [];
    try {
      const [assessmentRows] = await pool.query(`
      SELECT a.*, s.assignment_id
      FROM assessments a
      JOIN submission s ON a.submission_id = s.submission_id
      WHERE s.assignment_id = ?
    `, [assignmentId]);
      assessments = assessmentRows;
    console.log(`✅ Found ${assessments.length} assessments`);
    } catch (assessmentError) {
      console.error('❌ Error fetching assessments:', assessmentError.message);
      // Don't return error, just continue with empty assessments
      assessments = [];
    }
    
    // Combine data
    console.log('🔗 Combining student data...');
    const result = students.map(student => {
      const submission = submissions.find(s => s.user_id === student.user_id);
      const assessment = assessments.find(a => a.assessed_user_id === student.user_id);
      
      return {
        ...student,
        has_submitted: !!submission,
        submission: submission || null,
        assessment: assessment || null
      };
    });
    
    console.log(`✅ Returning ${result.length} students with combined data`);
    res.json(result);
  } catch (err) {
    console.error('❌ Error fetching students:', err);
    console.error('❌ Error details:', err.message);
    console.error('❌ Error stack:', err.stack);
    res.status(500).json({ 
      message: 'Failed to fetch students.',
      error: err.message,
      stack: err.stack
    });
  }
});

// Create or update assessment
app.post('/api/assessments', async (req, res) => {
  try {
    const {
      submission_id,
      assessed_user_id,
      assessor_user_id,
      assessment_type,
      score,
      comments,
      academic_year,
      semester
    } = req.body;
    
    console.log('📝 Creating/updating assessment with data:', {
      submission_id,
      assessed_user_id,
      assessor_user_id,
      assessment_type,
      score,
      academic_year,
      semester
    });
    
    // Check if assessment already exists
    const [existing] = await pool.query(`
      SELECT assessment_id FROM assessments 
      WHERE submission_id = ? AND assessed_user_id = ? AND assessor_user_id = ? AND assessment_type = ?
    `, [submission_id, assessed_user_id, assessor_user_id, assessment_type]);
    
    if (existing.length > 0) {
      // Update existing assessment
      await pool.query(`
        UPDATE assessments 
        SET score = ?, comments = ?, assessment_date = NOW()
        WHERE assessment_id = ?
      `, [score, comments, existing[0].assessment_id]);
      
      console.log(`✅ Assessment updated: ${existing[0].assessment_id}`);
      res.json({ message: 'Assessment updated successfully.', assessment_id: existing[0].assessment_id });
    } else {
      // Create new assessment
      const [result] = await pool.query(`
        INSERT INTO assessments (
          submission_id, assessed_user_id, assessor_user_id, 
          assessment_type, score, comments, assessment_date, 
          academic_year, semester
        ) VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, ?)
      `, [submission_id, assessed_user_id, assessor_user_id, 
          assessment_type, score, comments, academic_year, semester]);
      
      console.log(`✅ Assessment created: ${result.insertId}`);
      res.status(201).json({ message: 'Assessment created successfully.', assessment_id: result.insertId });
    }
  } catch (err) {
    console.error('❌ Error creating/updating assessment:', err);
    console.error('❌ Error details:', err.message);
    res.status(500).json({ message: 'Failed to create/update assessment.', error: err.message });
  }
});

// Get assessment by ID
app.get('/api/assessments/:assessmentId', async (req, res) => {
  try {
    const { assessmentId } = req.params;
    const [rows] = await pool.query(`
      SELECT a.*, 
             u1.name as assessed_user_name,
             u2.name as assessor_user_name,
             s.google_drive_file_id,
             s.text as submission_text,
             ass.title as assignment_title
      FROM assessments a
      JOIN user u1 ON a.assessed_user_id = u1.user_id
      JOIN user u2 ON a.assessor_user_id = u2.user_id
      LEFT JOIN submission s ON a.submission_id = s.submission_id
      LEFT JOIN assignments ass ON s.assignment_id = ass.assignment_id
      WHERE a.assessment_id = ?
    `, [assessmentId]);
    
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Assessment not found.' });
    }
    
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching assessment:', err);
    res.status(500).json({ message: 'Failed to fetch assessment.' });
  }
});

// Update assessment
app.put('/api/assessments/:assessmentId', async (req, res) => {
  try {
    const { assessmentId } = req.params;
    const { score, comments } = req.body;
    
    console.log(`📝 Updating assessment ${assessmentId} with score: ${score}`);
    
    const [result] = await pool.query(`
      UPDATE assessments 
      SET score = ?, comments = ?, assessment_date = NOW()
      WHERE assessment_id = ?
    `, [score, comments, assessmentId]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Assessment not found.' });
    }
    
    console.log(`✅ Assessment ${assessmentId} updated successfully`);
    res.json({ message: 'Assessment updated successfully.' });
  } catch (err) {
    console.error('❌ Error updating assessment:', err);
    res.status(500).json({ message: 'Failed to update assessment.' });
  }
});

// Delete assessment
app.delete('/api/assessments/:assessmentId', async (req, res) => {
  try {
    const { assessmentId } = req.params;
    
    console.log(`🗑️ Deleting assessment ${assessmentId}`);
    
    const [result] = await pool.query('DELETE FROM assessments WHERE assessment_id = ?', [assessmentId]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Assessment not found.' });
    }
    
    console.log(`✅ Assessment ${assessmentId} deleted successfully`);
    res.json({ message: 'Assessment deleted successfully.' });
  } catch (err) {
    console.error('❌ Error deleting assessment:', err);
    res.status(500).json({ message: 'Failed to delete assessment.' });
  }
});

// Get assessment types
app.get('/api/assessment-types', async (req, res) => {
  try {
    const assessmentTypes = [
      { value: 'pre_conference', label: 'Pre Conference' },
      { value: 'post_conference', label: 'Post Conference' },
      { value: 'laporan_pendahuluan', label: 'Laporan Pendahuluan' },
      { value: 'asuhan_keperawatan', label: 'Asuhan Keperawatan' },
      { value: 'analisa_sintesa', label: 'Analisa Sintesa' },
      { value: 'sikap_mahasiswa', label: 'Sikap Mahasiswa' },
      { value: 'keterampilan_prosedural_klinik_dops', label: 'Keterampilan Prosedural Klinik DOPS' },
      { value: 'ujian_klinik', label: 'Ujian Klinik' },
      { value: 'telaah_artikel_jurnal', label: 'Telaah Artikel Jurnal' },
      { value: 'case_report', label: 'Case Report' }
    ];
    res.json(assessmentTypes);
  } catch (err) {
    console.error('Error fetching assessment types:', err);
    res.status(500).json({ message: 'Failed to fetch assessment types.' });
  }
});

// Get academic years from assessments
app.get('/api/academic-years', async (req, res) => {
  try {
    const [years] = await pool.query(`
      SELECT DISTINCT academic_year 
      FROM assessments 
      ORDER BY academic_year DESC
    `);
    res.json(years.map(row => row.academic_year));
  } catch (err) {
    console.error('❌ Error fetching academic years:', err);
    res.status(500).json({ message: 'Failed to fetch academic years.' });
  }
});

// Get semesters from assessments
app.get('/api/semesters', async (req, res) => {
  try {
    const [semesters] = await pool.query(`
      SELECT DISTINCT semester 
      FROM assessments 
      ORDER BY FIELD(semester, 'Ganjil', 'Genap', 'Pendek')
    `);
    res.json(semesters.map(row => row.semester));
  } catch (err) {
    console.error('❌ Error fetching semesters:', err);
    res.status(500).json({ message: 'Failed to fetch semesters.' });
  }
});

// Get all assessors (users who can assess)
app.get('/api/assessors', async (req, res) => {
  try {
    const [assessors] = await pool.query(`
      SELECT DISTINCT u.user_id, u.name, u.email, u.role
      FROM user u
      JOIN assessments a ON u.user_id = a.assessor_user_id
      ORDER BY u.name
    `);
    res.json(assessors);
  } catch (err) {
    console.error('❌ Error fetching assessors:', err);
    res.status(500).json({ message: 'Failed to fetch assessors.' });
  }
});

// Get all students who can be assessed
app.get('/api/assessed-students', async (req, res) => {
  try {
    const [students] = await pool.query(`
      SELECT DISTINCT u.user_id, u.name, u.email, u.prodi
      FROM user u
      JOIN assessments a ON u.user_id = a.assessed_user_id
      ORDER BY u.name
    `);
    res.json(students);
  } catch (err) {
    console.error('❌ Error fetching assessed students:', err);
    res.status(500).json({ message: 'Failed to fetch assessed students.' });
  }
});

// Get all students (for frontend)
app.get('/api/students', async (req, res) => {
  try {
    console.log('🔍 Fetching all students for frontend...');
    
    // First, let's check what roles exist in the database
    const [roleCheck] = await pool.query(`
      SELECT DISTINCT role, COUNT(*) as count
      FROM user 
      GROUP BY role
    `);
    console.log('🔍 Available roles in database:', roleCheck);
    
    // Get all students with mahasiswa role
    const [students] = await pool.query(`
      SELECT user_id, name, email, prodi, role
      FROM user 
      WHERE role = 'mahasiswa'
      ORDER BY name
    `);
    
    console.log(`✅ Found ${students.length} students for frontend`);
    res.json(students);
  } catch (err) {
    console.error('❌ Error fetching students for frontend:', err);
    console.error('❌ Error details:', err.message);
    res.status(500).json({ 
      message: 'Failed to fetch students for frontend.',
      error: err.message 
    });
  }
});

// Get individual user by ID
app.get('/api/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    console.log(`🔍 Fetching user: ${userId}`);
    
    const [users] = await pool.query(`
      SELECT user_id, name, email, prodi, role
      FROM user 
      WHERE user_id = ?
    `, [userId]);
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    
    console.log(`✅ Found user: ${users[0].name}`);
    res.json(users[0]);
  } catch (err) {
    console.error('❌ Error fetching user:', err);
    res.status(500).json({ message: 'Failed to fetch user.' });
  }
});

// Get all users (for admin)
app.get('/api/users', async (req, res) => {
  try {
    console.log('🔍 Fetching all users for admin...');
    
    const [users] = await pool.query(`
      SELECT user_id, name, email, prodi, role
      FROM user 
      ORDER BY name
    `);
    
    console.log(`✅ Found ${users.length} users for admin`);
    res.json(users);
  } catch (err) {
    console.error('❌ Error fetching users for admin:', err);
    res.status(500).json({ message: 'Failed to fetch users for admin.' });
  }
});

// Get students for assessment type (without assignment)
app.get('/api/assessment-types/:assessmentType/students', async (req, res) => {
  try {
    const { assessmentType } = req.params;
    const { academic_year, semester } = req.query;
    console.log(`🔍 Fetching students for assessment type: ${assessmentType}`);
    console.log(`📅 Academic year: ${academic_year}, Semester: ${semester}`);
    
    // First, test database connection
    const connection = await pool.getConnection();
    console.log('✅ Database connection successful');
    
    // Test if user table exists and has data
    try {
      const [userCount] = await connection.execute('SELECT COUNT(*) as count FROM user');
      console.log(`📊 User table has ${userCount[0].count} records`);
    } catch (userError) {
      console.error('❌ Error accessing user table:', userError.message);
      return res.status(500).json({ 
        message: 'Database table error', 
        error: 'User table not accessible',
        details: userError.message 
      });
    }
    
    // Test if assessments table exists
    try {
      const [assessmentCount] = await connection.execute('SELECT COUNT(*) as count FROM assessments');
      console.log(`📊 Assessments table has ${assessmentCount[0].count} records`);
    } catch (assessmentError) {
      console.error('❌ Error accessing assessments table:', assessmentError.message);
      return res.status(500).json({ 
        message: 'Database table error', 
        error: 'Assessments table not accessible',
        details: assessmentError.message 
      });
    }
    
    connection.release();
    
    // Get all students with better error handling
    console.log('📚 Fetching all students...');
    let students = [];
    try {
      // First, let's check what roles exist in the database
      const [roleCheck] = await pool.query(`
        SELECT DISTINCT role, COUNT(*) as count
        FROM user 
        GROUP BY role
      `);
      console.log('🔍 Available roles in database:', roleCheck);
      
      // Now fetch students with mahasiswa role
      const [studentRows] = await pool.query(`
        SELECT user_id, name, email, prodi, role
        FROM user 
        WHERE role = 'mahasiswa'
        ORDER BY name
      `);
      students = studentRows;
      console.log(`✅ Found ${students.length} students with role 'mahasiswa'`);
    } catch (studentError) {
      console.error('❌ Error fetching students:', studentError.message);
      return res.status(500).json({ 
        message: 'Failed to fetch students', 
        error: studentError.message 
      });
    }
    
    // Build query for existing assessments with better error handling
    let assessments = [];
    try {
      let assessmentQuery = `
        SELECT a.*, u.name as student_name, u.email, u.prodi
        FROM assessments a
        JOIN user u ON a.assessed_user_id = u.user_id
        WHERE a.assessment_type = ?
      `;
      let queryParams = [assessmentType];
      
      // Add academic year and semester filters if provided
      if (academic_year) {
        assessmentQuery += ' AND a.academic_year = ?';
        queryParams.push(academic_year);
      }
      if (semester) {
        assessmentQuery += ' AND a.semester = ?';
        queryParams.push(semester);
      }
      
      assessmentQuery += ' ORDER BY a.assessment_date DESC';
      
      console.log(`⭐ Fetching existing assessments for type ${assessmentType}...`);
      console.log('🔍 Assessment query:', assessmentQuery);
      console.log('📊 Query parameters:', queryParams);
      
      const [assessmentRows] = await pool.query(assessmentQuery, queryParams);
      assessments = assessmentRows;
      console.log(`✅ Found ${assessments.length} existing assessments`);
    } catch (assessmentError) {
      console.error('❌ Error fetching assessments:', assessmentError.message);
      console.error('❌ Assessment error details:', assessmentError);
      // Don't return error, just continue with empty assessments
      assessments = [];
    }
    
    // Combine data
    console.log('🔗 Combining student data...');
    const result = students.map(student => {
      const assessment = assessments.find(a => a.assessed_user_id === student.user_id);
      
      return {
        ...student,
        has_assessment: !!assessment,
        assessment: assessment || null
      };
    });
    
    console.log(`✅ Returning ${result.length} students with assessment data`);
    res.json(result);
  } catch (err) {
    console.error('❌ Error fetching students for assessment type:', err);
    console.error('❌ Error details:', err.message);
    console.error('❌ Error stack:', err.stack);
    res.status(500).json({ 
      message: 'Failed to fetch students for assessment type.',
      error: err.message,
      stack: err.stack
    });
  }
});

// Create assessment without submission (direct assessment)
app.post('/api/assessments/direct', async (req, res) => {
  try {
    const {
      assessed_user_id,
      assessor_user_id,
      assessment_type,
      score,
      comments,
      academic_year,
      semester
    } = req.body;
    
    console.log('📝 Creating/updating direct assessment with data:', {
      assessed_user_id,
      assessor_user_id,
      assessment_type,
      score,
      academic_year,
      semester
    });
    
    // Check if assessment already exists
    const [existing] = await pool.query(`
      SELECT assessment_id FROM assessments 
      WHERE assessed_user_id = ? AND assessor_user_id = ? AND assessment_type = ? AND academic_year = ? AND semester = ?
    `, [assessed_user_id, assessor_user_id, assessment_type, academic_year, semester]);
    
    if (existing.length > 0) {
      // Update existing assessment
        await pool.query(`
        UPDATE assessments 
        SET score = ?, comments = ?, assessment_date = NOW()
        WHERE assessment_id = ?
      `, [score, comments, existing[0].assessment_id]);
      
      console.log(`✅ Direct assessment updated: ${existing[0].assessment_id}`);
      res.json({ message: 'Assessment updated successfully.', assessment_id: existing[0].assessment_id });
    } else {
      // Create new assessment without submission
      const [result] = await pool.query(`
        INSERT INTO assessments (
          submission_id, assessed_user_id, assessor_user_id, 
          assessment_type, score, comments, assessment_date, 
          academic_year, semester
        ) VALUES (NULL, ?, ?, ?, ?, ?, NOW(), ?, ?)
      `, [assessed_user_id, assessor_user_id, assessment_type, score, comments, academic_year, semester]);
      
      console.log(`✅ Direct assessment created: ${result.insertId}`);
      res.status(201).json({ message: 'Assessment created successfully.', assessment_id: result.insertId });
    }
  } catch (err) {
    console.error('❌ Error creating/updating direct assessment:', err);
    console.error('❌ Error details:', err.message);
    res.status(500).json({ message: 'Failed to create/update assessment.', error: err.message });
  }
});

// Create detailed assessment with specific scoring tables
app.post('/api/assessments/detailed', async (req, res) => {
  // Get a connection for transaction
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    let {
      assessed_user_id,
      assessor_user_id,
      assessment_type,
      comments,
      academic_year,
      semester,
      assessment_data
    } = req.body;

    // Assignment-based assessment auto-assignment (always override)
    let assignment_id = null;
    switch (assessment_type) {
      case 'laporan_pendahuluan':
        assignment_id = 1;
        break;
      case 'asuhan_keperawatan':
      case 'analisa_sintesa':
        assignment_id = 2;
        break;
      case 'case_report':
        assignment_id = 3;
        break;
      case 'telaah_artikel_jurnal':
        assignment_id = 5;
        break;
      // all other types: assignment_id remains null
    }

    // Check if assessment already exists
    let existingQuery = '';
    let existingParams = [];
    existingQuery = `
      SELECT assessment_id FROM assessments 
      WHERE assessed_user_id = ? AND assessor_user_id = ? AND assessment_type = ? AND academic_year = ? AND semester = ?
    `;
    existingParams = [assessed_user_id, assessor_user_id, assessment_type, academic_year, semester];
    const [existing] = await connection.query(existingQuery, existingParams);
    let assessmentId;
    if (existing.length > 0) {
      assessmentId = existing[0].assessment_id;
      await connection.query(`
        UPDATE assessments 
        SET comments = ?, assessment_date = NOW()
        WHERE assessment_id = ?
      `, [comments, assessmentId]);
      console.log(`✅ Assessment updated: ${assessmentId}`);
    } else {
      // Create new assessment
      const safeComments = (typeof comments === 'string') ? comments : '';
      const [result] = await connection.query(`
        INSERT INTO assessments (
          submission_id, assessed_user_id, assessor_user_id, 
          assessment_type, score, comments, assessment_date, 
          academic_year, semester
        ) VALUES (NULL, ?, ?, ?, ?, ?, NOW(), ?, ?)
      `, [assessed_user_id, assessor_user_id, assessment_type, null, safeComments, academic_year, semester]);
      assessmentId = result.insertId;
      console.log(`✅ Assessment created: ${assessmentId}`);
    }
    
    // Verify assessment exists
    const [verifyAssessment] = await connection.query(`
      SELECT * FROM assessments WHERE assessment_id = ?
    `, [assessmentId]);
    console.log(`🔍 Verification - Assessment exists:`, verifyAssessment.length > 0);
    if (verifyAssessment.length > 0) {
      console.log(`📋 Assessment details:`, verifyAssessment[0]);
    }
    
    // Insert detailed scoring based on assessment type
    switch (assessment_type) {
      case 'pre_conference':
        console.log(`📊 Inserting pre_conference data for assessment ${assessmentId}:`, assessment_data);
        
        // Validate assessment_data exists and has required fields
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for pre_conference`);
          throw new Error('Assessment data is required for pre_conference assessment');
        }
        
        // Check if all required fields are present
        const preconRequiredFields = ['aspect_precon_1', 'aspect_precon_2', 'aspect_precon_3', 'aspect_precon_4', 'aspect_precon_5'];
        const preconMissingFields = preconRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (preconMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, preconMissingFields);
          throw new Error(`Missing required fields: ${preconMissingFields.join(', ')}`);
        }
        
        // Convert to integers and validate
        const preconValues = [
          parseInt(assessment_data.aspect_precon_1) || 0,
          parseInt(assessment_data.aspect_precon_2) || 0,
          parseInt(assessment_data.aspect_precon_3) || 0,
          parseInt(assessment_data.aspect_precon_4) || 0,
          parseInt(assessment_data.aspect_precon_5) || 0
        ];
        
        console.log(`📊 Converted pre-conference values:`, preconValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO penilaian_pre_conference (
              assessment_id, aspect_precon_1, aspect_precon_2, aspect_precon_3, 
              aspect_precon_4, aspect_precon_5
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspect_precon_1 = VALUES(aspect_precon_1),
              aspect_precon_2 = VALUES(aspect_precon_2),
              aspect_precon_3 = VALUES(aspect_precon_3),
              aspect_precon_4 = VALUES(aspect_precon_4),
              aspect_precon_5 = VALUES(aspect_precon_5)
          `, [assessmentId, ...preconValues]);
          
          console.log(`✅ Pre-conference data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Inserted detailed data:`, {
            assessment_id: assessmentId,
            aspect_precon_1: preconValues[0],
            aspect_precon_2: preconValues[1],
            aspect_precon_3: preconValues[2],
            aspect_precon_4: preconValues[3],
            aspect_precon_5: preconValues[4]
          });
          
          // Verify the insertion
          const [verifyInsert] = await connection.query(`
            SELECT * FROM penilaian_pre_conference WHERE assessment_id = ?
          `, [assessmentId]);
          console.log(`🔍 Verification - Penilaian data exists:`, verifyInsert.length > 0);
          if (verifyInsert.length > 0) {
            console.log(`📋 Penilaian details:`, verifyInsert[0]);
          }
          
        } catch (error) {
          console.error(`❌ Error saving pre-conference data:`, error);
          console.error(`❌ Error details:`, error.message);
          console.error(`❌ Error code:`, error.code);
          throw error;
        }
        break;
        
      case 'post_conference':
        console.log(`📊 Inserting post_conference data for assessment ${assessmentId}:`, assessment_data);
        
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for post_conference`);
          throw new Error('Assessment data is required for post_conference assessment');
        }
        
        const postconRequiredFields = ['aspect_postcon_1', 'aspect_postcon_2', 'aspect_postcon_3', 'aspect_postcon_4', 'aspect_postcon_5'];
        const postconMissingFields = postconRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (postconMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, postconMissingFields);
          throw new Error(`Missing required fields: ${postconMissingFields.join(', ')}`);
        }
        
        const postconValues = [
          parseInt(assessment_data.aspect_postcon_1) || 0,
          parseInt(assessment_data.aspect_postcon_2) || 0,
          parseInt(assessment_data.aspect_postcon_3) || 0,
          parseInt(assessment_data.aspect_postcon_4) || 0,
          parseInt(assessment_data.aspect_postcon_5) || 0
        ];
        
        console.log(`📊 Converted post-conference values:`, postconValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO penilaian_post_conference (
              assessment_id, aspect_postcon_1, aspect_postcon_2, aspect_postcon_3, 
              aspect_postcon_4, aspect_postcon_5
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspect_postcon_1 = VALUES(aspect_postcon_1),
              aspect_postcon_2 = VALUES(aspect_postcon_2),
              aspect_postcon_3 = VALUES(aspect_postcon_3),
              aspect_postcon_4 = VALUES(aspect_postcon_4),
              aspect_postcon_5 = VALUES(aspect_postcon_5)
          `, [assessmentId, ...postconValues]);
          
          console.log(`✅ Post-conference data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Insert result:`, insertResult);
          
        } catch (error) {
          console.error(`❌ Error saving post-conference data:`, error);
          throw error;
        }
        break;
        
      case 'laporan_pendahuluan':
        console.log(`📊 Inserting laporan_pendahuluan data for assessment ${assessmentId}:`, assessment_data);
        
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for laporan_pendahuluan`);
          throw new Error('Assessment data is required for laporan_pendahuluan assessment');
        }
        
        const lappenRequiredFields = ['aspect_lappen_1', 'aspect_lappen_2', 'aspect_lappen_3', 'aspect_lappen_4'];
        const lappenMissingFields = lappenRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (lappenMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, lappenMissingFields);
          throw new Error(`Missing required fields: ${lappenMissingFields.join(', ')}`);
        }
        
        const lappenValues = [
          parseInt(assessment_data.aspect_lappen_1) || 0,
          parseInt(assessment_data.aspect_lappen_2) || 0,
          parseInt(assessment_data.aspect_lappen_3) || 0,
          parseInt(assessment_data.aspect_lappen_4) || 0
        ];
        
        console.log(`📊 Converted laporan pendahuluan values:`, lappenValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO penilaian_laporan_pendahuluan (
              assessment_id, aspect_lappen_1, aspect_lappen_2, aspect_lappen_3, aspect_lappen_4
            ) VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspect_lappen_1 = VALUES(aspect_lappen_1),
              aspect_lappen_2 = VALUES(aspect_lappen_2),
              aspect_lappen_3 = VALUES(aspect_lappen_3),
              aspect_lappen_4 = VALUES(aspect_lappen_4)
          `, [assessmentId, ...lappenValues]);
          
          console.log(`✅ Laporan pendahuluan data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Insert result:`, insertResult);
          
        } catch (error) {
          console.error(`❌ Error saving laporan pendahuluan data:`, error);
          throw error;
        }
        break;
        
      case 'asuhan_keperawatan':
      case 'analisa_sintesa':
        console.log(`📊 Inserting laporan data for assessment ${assessmentId} (${assessment_type}):`, assessment_data);
        
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for ${assessment_type}`);
          throw new Error(`Assessment data is required for ${assessment_type} assessment`);
        }
        
        const laporanRequiredFields = ['aspect_laporan_1', 'aspect_laporan_2', 'aspect_laporan_3', 'aspect_laporan_4', 'aspect_laporan_5', 'aspect_laporan_6', 'aspect_laporan_7', 'aspect_laporan_8', 'aspect_laporan_9', 'aspect_laporan_10'];
        const laporanMissingFields = laporanRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (laporanMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, laporanMissingFields);
          throw new Error(`Missing required fields: ${laporanMissingFields.join(', ')}`);
        }
        
        const laporanValues = [
          parseInt(assessment_data.aspect_laporan_1) || 0,
          parseInt(assessment_data.aspect_laporan_2) || 0,
          parseInt(assessment_data.aspect_laporan_3) || 0,
          parseInt(assessment_data.aspect_laporan_4) || 0,
          parseInt(assessment_data.aspect_laporan_5) || 0,
          parseInt(assessment_data.aspect_laporan_6) || 0,
          parseInt(assessment_data.aspect_laporan_7) || 0,
          parseInt(assessment_data.aspect_laporan_8) || 0,
          parseInt(assessment_data.aspect_laporan_9) || 0,
          parseInt(assessment_data.aspect_laporan_10) || 0
        ];
        
        console.log(`📊 Converted laporan values:`, laporanValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO penilaian_laporan (
              assessment_id, aspect_laporan_1, aspect_laporan_2, aspect_laporan_3, 
              aspect_laporan_4, aspect_laporan_5, aspect_laporan_6, aspect_laporan_7, 
              aspect_laporan_8, aspect_laporan_9, aspect_laporan_10
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspect_laporan_1 = VALUES(aspect_laporan_1),
              aspect_laporan_2 = VALUES(aspect_laporan_2),
              aspect_laporan_3 = VALUES(aspect_laporan_3),
              aspect_laporan_4 = VALUES(aspect_laporan_4),
              aspect_laporan_5 = VALUES(aspect_laporan_5),
              aspect_laporan_6 = VALUES(aspect_laporan_6),
              aspect_laporan_7 = VALUES(aspect_laporan_7),
              aspect_laporan_8 = VALUES(aspect_laporan_8),
              aspect_laporan_9 = VALUES(aspect_laporan_9),
              aspect_laporan_10 = VALUES(aspect_laporan_10)
          `, [assessmentId, ...laporanValues]);
          
          console.log(`✅ Laporan data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Insert result:`, insertResult);
          
        } catch (error) {
          console.error(`❌ Error saving laporan data:`, error);
          throw error;
        }
        break;
        
      case 'sikap_mahasiswa':
        console.log(`📊 Inserting sikap_mahasiswa data for assessment ${assessmentId}:`, assessment_data);
        
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for sikap_mahasiswa`);
          throw new Error('Assessment data is required for sikap_mahasiswa assessment');
        }
        
        const sikapRequiredFields = Array.from({length: 20}, (_, i) => `aspek_sikap_${i + 1}`);
        const sikapMissingFields = sikapRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (sikapMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, sikapMissingFields);
          throw new Error(`Missing required fields: ${sikapMissingFields.join(', ')}`);
        }
        
        const sikapValues = sikapRequiredFields.map(field => parseInt(assessment_data[field]) || 0);
        
        console.log(`📊 Converted sikap mahasiswa values:`, sikapValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO penilaian_sikap_mahasiswa (
              assessment_id, aspek_sikap_1, aspek_sikap_2, aspek_sikap_3, aspek_sikap_4, aspek_sikap_5,
              aspek_sikap_6, aspek_sikap_7, aspek_sikap_8, aspek_sikap_9, aspek_sikap_10,
              aspek_sikap_11, aspek_sikap_12, aspek_sikap_13, aspek_sikap_14, aspek_sikap_15,
              aspek_sikap_16, aspek_sikap_17, aspek_sikap_18, aspek_sikap_19, aspek_sikap_20
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspek_sikap_1 = VALUES(aspek_sikap_1), aspek_sikap_2 = VALUES(aspek_sikap_2),
              aspek_sikap_3 = VALUES(aspek_sikap_3), aspek_sikap_4 = VALUES(aspek_sikap_4),
              aspek_sikap_5 = VALUES(aspek_sikap_5), aspek_sikap_6 = VALUES(aspek_sikap_6),
              aspek_sikap_7 = VALUES(aspek_sikap_7), aspek_sikap_8 = VALUES(aspek_sikap_8),
              aspek_sikap_9 = VALUES(aspek_sikap_9), aspek_sikap_10 = VALUES(aspek_sikap_10),
              aspek_sikap_11 = VALUES(aspek_sikap_11), aspek_sikap_12 = VALUES(aspek_sikap_12),
              aspek_sikap_13 = VALUES(aspek_sikap_13), aspek_sikap_14 = VALUES(aspek_sikap_14),
              aspek_sikap_15 = VALUES(aspek_sikap_15), aspek_sikap_16 = VALUES(aspek_sikap_16),
              aspek_sikap_17 = VALUES(aspek_sikap_17), aspek_sikap_18 = VALUES(aspek_sikap_18),
              aspek_sikap_19 = VALUES(aspek_sikap_19), aspek_sikap_20 = VALUES(aspek_sikap_20)
          `, [assessmentId, ...sikapValues]);
          
          console.log(`✅ Sikap mahasiswa data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Insert result:`, insertResult);
          
        } catch (error) {
          console.error(`❌ Error saving sikap mahasiswa data:`, error);
          throw error;
        }
        break;
        
      case 'keterampilan_prosedural_klinik_dops':
        console.log(`📊 Inserting keterampilan_prosedural_klinik_dops data for assessment ${assessmentId}:`, assessment_data);
        
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for keterampilan_prosedural_klinik_dops`);
          throw new Error('Assessment data is required for keterampilan_prosedural_klinik_dops assessment');
        }
        
        const dopsRequiredFields = Array.from({length: 16}, (_, i) => `aspect_dops_${i + 1}`);
        const dopsMissingFields = dopsRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (dopsMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, dopsMissingFields);
          throw new Error(`Missing required fields: ${dopsMissingFields.join(', ')}`);
        }
        
        const dopsValues = dopsRequiredFields.map(field => parseInt(assessment_data[field]) || 0);
        
        console.log(`📊 Converted DOPS values:`, dopsValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO keterampilan_prosedural_klinik (
              assessment_id, aspect_dops_1, aspect_dops_2, aspect_dops_3, aspect_dops_4, aspect_dops_5,
              aspect_dops_6, aspect_dops_7, aspect_dops_8, aspect_dops_9, aspect_dops_10,
              aspect_dops_11, aspect_dops_12, aspect_dops_13, aspect_dops_14, aspect_dops_15, aspect_dops_16
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspect_dops_1 = VALUES(aspect_dops_1), aspect_dops_2 = VALUES(aspect_dops_2),
              aspect_dops_3 = VALUES(aspect_dops_3), aspect_dops_4 = VALUES(aspect_dops_4),
              aspect_dops_5 = VALUES(aspect_dops_5), aspect_dops_6 = VALUES(aspect_dops_6),
              aspect_dops_7 = VALUES(aspect_dops_7), aspect_dops_8 = VALUES(aspect_dops_8),
              aspect_dops_9 = VALUES(aspect_dops_9), aspect_dops_10 = VALUES(aspect_dops_10),
              aspect_dops_11 = VALUES(aspect_dops_11), aspect_dops_12 = VALUES(aspect_dops_12),
              aspect_dops_13 = VALUES(aspect_dops_13), aspect_dops_14 = VALUES(aspect_dops_14),
              aspect_dops_15 = VALUES(aspect_dops_15), aspect_dops_16 = VALUES(aspect_dops_16)
          `, [assessmentId, ...dopsValues]);
          
          console.log(`✅ DOPS data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Insert result:`, insertResult);
          
        } catch (error) {
          console.error(`❌ Error saving DOPS data:`, error);
          throw error;
        }
        break;
        
      case 'ujian_klinik':
        console.log(`📊 Inserting ujian_klinik data for assessment ${assessmentId}:`, assessment_data);
        
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for ujian_klinik`);
          throw new Error('Assessment data is required for ujian_klinik assessment');
        }
        
        const klinikRequiredFields = ['aspek_klinik_1', 'aspek_klinik_2', 'aspek_klinik_3', 'aspek_klinik_4', 'aspek_klinik_5a', 'aspek_klinik_5b', 'aspek_klinik_6', 'aspek_klinik_7', 'aspek_klinik_8', 'aspek_klinik_9', 'aspek_klinik_10', 'aspek_klinik_11', 'aspek_klinik_12', 'aspek_klinik_13', 'aspek_klinik_14', 'aspek_klinik_15', 'aspek_klinik_16', 'aspek_klinik_17', 'aspek_klinik_18'];
        const klinikMissingFields = klinikRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (klinikMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, klinikMissingFields);
          throw new Error(`Missing required fields: ${klinikMissingFields.join(', ')}`);
        }
        
        const klinikValues = klinikRequiredFields.map(field => parseInt(assessment_data[field]) || 0);
        
        console.log(`📊 Converted ujian klinik values:`, klinikValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO penilaian_ujian_klinik (
              assessment_id, aspek_klinik_1, aspek_klinik_2, aspek_klinik_3, aspek_klinik_4,
              aspek_klinik_5a, aspek_klinik_5b, aspek_klinik_6, aspek_klinik_7, aspek_klinik_8,
              aspek_klinik_9, aspek_klinik_10, aspek_klinik_11, aspek_klinik_12, aspek_klinik_13,
              aspek_klinik_14, aspek_klinik_15, aspek_klinik_16, aspek_klinik_17, aspek_klinik_18
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspek_klinik_1 = VALUES(aspek_klinik_1), aspek_klinik_2 = VALUES(aspek_klinik_2),
              aspek_klinik_3 = VALUES(aspek_klinik_3), aspek_klinik_4 = VALUES(aspek_klinik_4),
              aspek_klinik_5a = VALUES(aspek_klinik_5a), aspek_klinik_5b = VALUES(aspek_klinik_5b),
              aspek_klinik_6 = VALUES(aspek_klinik_6), aspek_klinik_7 = VALUES(aspek_klinik_7),
              aspek_klinik_8 = VALUES(aspek_klinik_8), aspek_klinik_9 = VALUES(aspek_klinik_9),
              aspek_klinik_10 = VALUES(aspek_klinik_10), aspek_klinik_11 = VALUES(aspek_klinik_11),
              aspek_klinik_12 = VALUES(aspek_klinik_12), aspek_klinik_13 = VALUES(aspek_klinik_13),
              aspek_klinik_14 = VALUES(aspek_klinik_14), aspek_klinik_15 = VALUES(aspek_klinik_15),
              aspek_klinik_16 = VALUES(aspek_klinik_16), aspek_klinik_17 = VALUES(aspek_klinik_17),
              aspek_klinik_18 = VALUES(aspek_klinik_18)
          `, [assessmentId, ...klinikValues]);
          
          console.log(`✅ Ujian klinik data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Insert result:`, insertResult);
          
        } catch (error) {
          console.error(`❌ Error saving ujian klinik data:`, error);
          throw error;
        }
        break;
        
      case 'telaah_artikel_jurnal':
        console.log(`📊 Inserting telaah_artikel_jurnal data for assessment ${assessmentId}:`, assessment_data);
        
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for telaah_artikel_jurnal`);
          throw new Error('Assessment data is required for telaah_artikel_jurnal assessment');
        }
        
        const telaahRequiredFields = Array.from({length: 5}, (_, i) => `aspect_jurnal_${i + 1}`);
        const telaahMissingFields = telaahRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (telaahMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, telaahMissingFields);
          throw new Error(`Missing required fields: ${telaahMissingFields.join(', ')}`);
        }
        
        const telaahValues = telaahRequiredFields.map(field => parseInt(assessment_data[field]) || 0);
        
        console.log(`📊 Converted telaah artikel jurnal values:`, telaahValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO telaah_artikel_jurnal (
              assessment_id, aspect_jurnal_1, aspect_jurnal_2, aspect_jurnal_3, 
              aspect_jurnal_4, aspect_jurnal_5
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspect_jurnal_1 = VALUES(aspect_jurnal_1),
              aspect_jurnal_2 = VALUES(aspect_jurnal_2),
              aspect_jurnal_3 = VALUES(aspect_jurnal_3),
              aspect_jurnal_4 = VALUES(aspect_jurnal_4),
              aspect_jurnal_5 = VALUES(aspect_jurnal_5)
          `, [assessmentId, ...telaahValues]);
          
          console.log(`✅ Telaah artikel jurnal data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Insert result:`, insertResult);
          
        } catch (error) {
          console.error(`❌ Error saving telaah artikel jurnal data:`, error);
          throw error;
        }
        break;
        
      case 'case_report':
        console.log(`📊 Inserting case_report data for assessment ${assessmentId}:`, assessment_data);
        
        if (!assessment_data) {
          console.error(`❌ No assessment_data provided for case_report`);
          throw new Error('Assessment data is required for case_report assessment');
        }
        
        const caseRequiredFields = Array.from({length: 4}, (_, i) => `aspek_casport_${i + 1}`);
        const caseMissingFields = caseRequiredFields.filter(field => assessment_data[field] === undefined || assessment_data[field] === null);
        
        if (caseMissingFields.length > 0) {
          console.error(`❌ Missing required fields:`, caseMissingFields);
          throw new Error(`Missing required fields: ${caseMissingFields.join(', ')}`);
        }
        
        const caseValues = caseRequiredFields.map(field => parseInt(assessment_data[field]) || 0);
        
        console.log(`📊 Converted case report values:`, caseValues);
        
        try {
          const insertResult = await connection.query(`
            INSERT INTO penilaian_case_report (
              assessment_id, aspek_casport_1, aspek_casport_2, aspek_casport_3, aspek_casport_4
            ) VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              aspek_casport_1 = VALUES(aspek_casport_1),
              aspek_casport_2 = VALUES(aspek_casport_2),
              aspek_casport_3 = VALUES(aspek_casport_3),
              aspek_casport_4 = VALUES(aspek_casport_4)
          `, [assessmentId, ...caseValues]);
          
          console.log(`✅ Case report data saved successfully for assessment ${assessmentId}`);
          console.log(`📊 Insert result:`, insertResult);
          
        } catch (error) {
          console.error(`❌ Error saving case report data:`, error);
          throw error;
        }
        break;
        


        
      default:
        throw new Error(`Unsupported assessment type: ${assessment_type}`);
    }
    
    console.log(`✅ Detailed assessment ${assessment_type} saved successfully`);
    
    // Commit the transaction
    await connection.commit();
    console.log(`✅ Transaction committed successfully`);
    
    res.status(201).json({ 
      message: 'Detailed assessment created successfully.', 
      assessment_id: assessmentId 
    });
    
  } catch (err) {
    // Rollback the transaction on error
    await connection.rollback();
    console.error('❌ Error creating detailed assessment:', err);
    console.error('❌ Error details:', err.message);
    res.status(500).json({ message: 'Failed to create detailed assessment.', error: err.message });
  } finally {
    // Release the connection
    connection.release();
  }
});

// Bulk create assessments for multiple students
app.post('/api/assessments/bulk', async (req, res) => {
  try {
    const {
      assessor_user_id,
      assessment_type,
      academic_year,
      semester,
      assessments // Array of { assessed_user_id, score, comments }
    } = req.body;
    
    console.log(`📝 Bulk creating ${assessments.length} assessments`);
    console.log('📊 Assessment data:', {
      assessor_user_id,
      assessment_type,
      academic_year,
      semester,
      count: assessments.length
    });
    
    const results = [];
    const errors = [];
    
    for (const assessment of assessments) {
      try {
        const { assessed_user_id, score, comments } = assessment;
        
        // Check if assessment already exists
        const [existing] = await pool.query(`
          SELECT assessment_id FROM assessments 
          WHERE assessed_user_id = ? AND assessor_user_id = ? AND assessment_type = ? AND academic_year = ? AND semester = ?
        `, [assessed_user_id, assessor_user_id, assessment_type, academic_year, semester]);
        
        if (existing.length > 0) {
          // Update existing assessment
        await pool.query(`
            UPDATE assessments 
            SET score = ?, comments = ?, assessment_date = NOW()
            WHERE assessment_id = ?
          `, [score, comments, existing[0].assessment_id]);
          
          results.push({
            assessed_user_id,
            assessment_id: existing[0].assessment_id,
            action: 'updated'
          });
        } else {
          // Create new assessment
          const [result] = await pool.query(`
            INSERT INTO assessments (
              submission_id, assessed_user_id, assessor_user_id, 
              assessment_type, score, comments, assessment_date, 
              academic_year, semester
            ) VALUES (NULL, ?, ?, ?, ?, ?, NOW(), ?, ?)
          `, [assessed_user_id, assessor_user_id, assessment_type, score, comments, academic_year, semester]);
          
          results.push({
            assessed_user_id,
            assessment_id: result.insertId,
            action: 'created'
          });
        }
      } catch (error) {
        console.error(`❌ Error processing assessment for user ${assessment.assessed_user_id}:`, error);
        errors.push({
          assessed_user_id: assessment.assessed_user_id,
          error: error.message
        });
      }
    }
    
    console.log(`✅ Bulk assessment completed. Success: ${results.length}, Errors: ${errors.length}`);
    
    res.status(201).json({
      message: 'Bulk assessment completed',
      results,
      errors,
      summary: {
        total: assessments.length,
        successful: results.length,
        failed: errors.length
      }
    });
  } catch (err) {
    console.error('❌ Error in bulk assessment:', err);
    res.status(500).json({ message: 'Failed to create bulk assessments.', error: err.message });
  }
});

// Get assessments for a specific user
app.get('/api/users/:userId/assessments', async (req, res) => {
  try {
    const { userId } = req.params;
    console.log(`🔍 Fetching assessments for user: ${userId}`);
    const [assessments] = await pool.query(`
      SELECT 
        a.assessment_id,
        a.assessment_type,
        a.score,
        a.comments,
        a.assessment_date,
        a.academic_year,
        a.semester,
        u.name as assessor_name,
        ass.title as assignment_title,
        ass.assignment_id,
        s.submission_id,
        s.submitted_at
      FROM assessments a
      LEFT JOIN user u ON a.assessor_user_id = u.user_id
      LEFT JOIN submission s ON a.submission_id = s.submission_id
      LEFT JOIN assignments ass ON s.assignment_id = ass.assignment_id
      WHERE a.assessed_user_id = ?
      ORDER BY a.assessment_date DESC
    `, [userId]);

    // For each assessment, fetch final score from detail table if available
    const results = await Promise.all(assessments.map(async (a) => {
      let finalScore = null;
      try {
        switch (a.assessment_type) {
          case 'pre_conference': {
            const [rows] = await pool.query('SELECT nilai_akhir_precon as score FROM penilaian_pre_conference WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          case 'post_conference': {
            const [rows] = await pool.query('SELECT nilai_akhir_postcon as score FROM penilaian_post_conference WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          case 'sikap_mahasiswa': {
            const [rows] = await pool.query('SELECT nilai_akhir_sikap as score FROM penilaian_sikap_mahasiswa WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          case 'keterampilan_prosedural_klinik_dops': {
            const [rows] = await pool.query('SELECT nilai_akhir_dops as score FROM keterampilan_prosedural_klinik WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          case 'ujian_klinik': {
            const [rows] = await pool.query('SELECT nilai_akhir_klinik as score FROM penilaian_ujian_klinik WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          case 'laporan_pendahuluan': {
            const [rows] = await pool.query('SELECT nilai_akhir_lappen as score FROM penilaian_laporan_pendahuluan WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          case 'asuhan_keperawatan':
          case 'analisa_sintesa': {
            const [rows] = await pool.query('SELECT nilai_akhir_laporan as score FROM penilaian_laporan WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          case 'telaah_artikel_jurnal': {
            const [rows] = await pool.query('SELECT nilai_akhir_jurnal as score FROM telaah_artikel_jurnal WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          case 'case_report': {
            const [rows] = await pool.query('SELECT nilai_akhir_casport as score FROM penilaian_case_report WHERE assessment_id = ?', [a.assessment_id]);
            finalScore = rows[0]?.score ?? null;
            break;
          }
          default:
            finalScore = a.score ?? null;
        }
      } catch (err) {
        finalScore = a.score ?? null;
      }
      return {
        ...a,
        score: finalScore
      };
    }));

    res.json(results);
  } catch (err) {
    console.error('❌ Error fetching user assessments:', err);
    res.status(500).json({ message: 'Failed to fetch user assessments.' });
  }
});

// Get assessments for a specific user and assessment type
app.get('/api/users/:userId/assessments/:assessmentType', async (req, res) => {
  try {
    const { userId, assessmentType } = req.params;
    console.log(`🔍 Fetching ${assessmentType} assessments for user: ${userId}`);
    const sql = `
      SELECT 
        a.assessment_id,
        a.assessment_type,
        a.score,
        a.comments,
        a.assessment_date,
        a.academic_year,
        a.semester,
        u.name as assessor_name,
        ass.title as assignment_title,
        ass.assignment_id,
        s.submission_id,
        s.submitted_at
      FROM assessments a
      LEFT JOIN user u ON a.assessor_user_id = u.user_id
      LEFT JOIN submission s ON a.submission_id = s.submission_id
      LEFT JOIN assignments ass ON s.assignment_id = ass.assignment_id
      WHERE a.assessed_user_id = ? AND a.assessment_type = ?
      ORDER BY a.assessment_date DESC
    `;
    console.log('SQL:', sql);
    console.log('Params:', [userId, assessmentType]);
    const [assessments] = await pool.query(sql, [userId, assessmentType]);
    console.log('Result:', assessments);
    res.json(assessments);
  } catch (err) {
    console.error('❌ Error fetching user assessments by type:', err);
    console.error('❌ Error details:', err.message);
    res.status(500).json({ message: 'Failed to fetch user assessments by type.' });
  }
});

// Get detailed assessment data for a specific assessment
app.get('/api/assessments/:assessmentId/detailed', async (req, res) => {
  try {
    const { assessmentId } = req.params;
    // First get the basic assessment info
    const [assessments] = await pool.query(`
      SELECT * FROM assessments WHERE assessment_id = ?
    `, [assessmentId]);
    if (assessments.length === 0) {
      return res.status(404).json({ message: 'Assessment not found.' });
    }
    const assessment = assessments[0];
    let detailedData = null;
    if (assessment.assessment_type && assessment.assessment_type.trim() === 'pre_conference') {
      const [preconData] = await pool.query(`
        SELECT * FROM penilaian_pre_conference WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] pre_conference', { assessmentId, preconData });
      detailedData = preconData[0] || null;
    } else if (assessment.assessment_type && assessment.assessment_type.trim() === 'post_conference') {
      const [postconData] = await pool.query(`
        SELECT * FROM penilaian_post_conference WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] post_conference', { assessmentId, postconData });
      detailedData = postconData[0] || null;
    } else if (assessment.assessment_type && assessment.assessment_type.trim() === 'laporan_pendahuluan') {
      const [lappenData] = await pool.query(`
        SELECT * FROM penilaian_laporan_pendahuluan WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] laporan_pendahuluan', { assessmentId, lappenData });
      detailedData = lappenData[0] || null;
    } else if (assessment.assessment_type && (assessment.assessment_type.trim() === 'asuhan_keperawatan' || assessment.assessment_type.trim() === 'analisa_sintesa')) {
      const [laporanData] = await pool.query(`
        SELECT * FROM penilaian_laporan WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] laporan', { assessmentId, laporanData });
      detailedData = laporanData[0] || null;
    } else if (assessment.assessment_type && assessment.assessment_type.trim() === 'telaah_artikel_jurnal') {
      const [jurnalData] = await pool.query(`
        SELECT * FROM telaah_artikel_jurnal WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] telaah_artikel_jurnal', { assessmentId, jurnalData });
      detailedData = jurnalData[0] || null;
    } else if (assessment.assessment_type && assessment.assessment_type.trim() === 'case_report') {
      const [caseData] = await pool.query(`
        SELECT * FROM penilaian_case_report WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] case_report', { assessmentId, caseData });
      detailedData = caseData[0] || null;
    } else if (assessment.assessment_type && assessment.assessment_type.trim() === 'sikap_mahasiswa') {
      const [sikapData] = await pool.query(`
        SELECT * FROM penilaian_sikap_mahasiswa WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] sikap_mahasiswa', { assessmentId, sikapData });
      detailedData = sikapData[0] || null;
    } else if (assessment.assessment_type && assessment.assessment_type.trim() === 'keterampilan_prosedural_klinik_dops') {
      const [dopsData] = await pool.query(`
        SELECT * FROM keterampilan_prosedural_klinik WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] keterampilan_prosedural_klinik_dops', { assessmentId, dopsData });
      detailedData = dopsData[0] || null;
    } else if (assessment.assessment_type && assessment.assessment_type.trim() === 'ujian_klinik') {
      const [klinikData] = await pool.query(`
        SELECT * FROM penilaian_ujian_klinik WHERE assessment_id = ?
      `, [assessmentId]);
      console.log('[DEBUG] ujian_klinik', { assessmentId, klinikData });
      detailedData = klinikData[0] || null;
    } else {
      console.log('[DEBUG] default case, assessment_type:', assessment.assessment_type);
      detailedData = null;
    }
    res.json({ assessment, detailed_data: detailedData });
  } catch (err) {
    console.error('Error fetching detailed assessment:', err);
    res.status(500).json({ message: 'Failed to fetch detailed assessment.' });
  }
});

// Test endpoint to check assessment data
app.get('/api/test/assessments', async (req, res) => {
  try {
    console.log('🔍 Testing assessment data...');
    
    // Check all assessments
    const [assessments] = await pool.query('SELECT * FROM assessments');
    console.log(`📊 Total assessments in database: ${assessments.length}`);
    console.log('📋 Assessment data:', assessments);
    
    // Check submissions
    const [submissions] = await pool.query('SELECT * FROM submission');
    console.log(`📊 Total submissions in database: ${submissions.length}`);
    console.log('📋 Submission data:', submissions);
    
    // Check assignments
    const [assignments] = await pool.query('SELECT * FROM assignments');
    console.log(`📊 Total assignments in database: ${assignments.length}`);
    console.log('📋 Assignment data:', assignments);
    
    // Check users
    const [users] = await pool.query('SELECT user_id, name, role FROM user');
    console.log(`📊 Total users in database: ${users.length}`);
    console.log('📋 User data:', users);
    
    res.json({
      message: 'Assessment data test completed',
      assessments: assessments.length,
      submissions: submissions.length,
      assignments: assignments.length,
      users: users.length,
      assessmentDetails: assessments,
      submissionDetails: submissions,
      assignmentDetails: assignments,
      userDetails: users
    });
  } catch (err) {
    console.error('❌ Error testing assessment data:', err);
    res.status(500).json({ message: 'Failed to test assessment data.', error: err.message });
  }
});

// Simple test route to fetch students
app.get('/api/test/students', async (req, res) => {
  try {
    console.log('🔍 Testing student fetching...');
    
    // Test 1: Get all users
    console.log('📚 Test 1: Getting all users...');
    const [allUsers] = await pool.query('SELECT user_id, name, email, role FROM user');
    console.log(`✅ Found ${allUsers.length} total users:`, allUsers);
    
    // Test 2: Get users with mahasiswa role
    console.log('📚 Test 2: Getting mahasiswa users...');
    const [mahasiswaUsers] = await pool.query(`
      SELECT user_id, name, email, role 
      FROM user 
      WHERE role = 'mahasiswa'
    `);
    console.log(`✅ Found ${mahasiswaUsers.length} mahasiswa users:`, mahasiswaUsers);
    
    // Test 3: Get users with any role containing 'student'
    console.log('📚 Test 3: Getting users with student-like roles...');
    const [studentLikeUsers] = await pool.query(`
      SELECT user_id, name, email, role 
      FROM user 
      WHERE role LIKE '%student%' OR role LIKE '%mahasiswa%'
    `);
    console.log(`✅ Found ${studentLikeUsers.length} student-like users:`, studentLikeUsers);
    
    // Test 4: Get all distinct roles
    console.log('📚 Test 4: Getting all distinct roles...');
    const [roles] = await pool.query(`
      SELECT DISTINCT role, COUNT(*) as count
      FROM user 
      GROUP BY role
    `);
    console.log(`✅ Found roles:`, roles);
    
    res.json({
      message: 'Student fetching test completed',
      allUsers: allUsers.length,
      mahasiswaUsers: mahasiswaUsers.length,
      studentLikeUsers: studentLikeUsers.length,
      roles: roles,
      allUsersDetails: allUsers,
      mahasiswaUsersDetails: mahasiswaUsers,
      studentLikeUsersDetails: studentLikeUsers
    });
  } catch (err) {
    console.error('❌ Error testing student fetching:', err);
    console.error('❌ Error details:', err.message);
    console.error('❌ Error stack:', err.stack);
    res.status(500).json({ 
      message: 'Failed to test student fetching.', 
      error: err.message,
      stack: err.stack
    });
  }
});

// Test the exact query that's failing
app.get('/api/test/students-exact', async (req, res) => {
  try {
    console.log('🔍 Testing the exact student query that might be failing...');
    
    // Test the exact query from the assignment students route
    console.log('📚 Testing exact query from assignment students route...');
    const [students] = await pool.query(`
      SELECT user_id, name, email, prodi, role
      FROM user 
      WHERE role = 'mahasiswa'
      ORDER BY name
    `);
    console.log(`✅ Found ${students.length} students with exact query`);
    console.log('📋 Students found:', students);
    
    res.json({
      message: 'Exact student query test completed',
      count: students.length,
      students: students
    });
  } catch (err) {
    console.error('❌ Error testing exact student query:', err);
    console.error('❌ Error details:', err.message);
    console.error('❌ Error stack:', err.stack);
    res.status(500).json({ 
      message: 'Failed to test exact student query.', 
      error: err.message,
      stack: err.stack
    });
  }
});

// Test penilaian tables
app.get('/api/test/penilaian-tables', async (req, res) => {
  try {
    console.log('🔍 Testing penilaian tables...');
    
    const results = {};
    
    // Test penilaian_pre_conference table
    try {
      const [preconTable] = await pool.query("SHOW TABLES LIKE 'penilaian_pre_conference'");
      if (preconTable.length > 0) {
        const [preconStructure] = await pool.query("DESCRIBE penilaian_pre_conference");
        const [preconData] = await pool.query("SELECT * FROM penilaian_pre_conference LIMIT 5");
        results.penilaian_pre_conference = {
          exists: true,
          structure: preconStructure,
          sample_data: preconData,
          count: preconData.length
        };
        console.log(`✅ penilaian_pre_conference table exists with ${preconData.length} records`);
      } else {
        results.penilaian_pre_conference = { exists: false };
        console.log('❌ penilaian_pre_conference table does not exist');
      }
    } catch (err) {
      results.penilaian_pre_conference = { error: err.message };
      console.log(`❌ Error checking penilaian_pre_conference: ${err.message}`);
    }
    
    // Test assessments table
    try {
      const [assessmentsData] = await pool.query("SELECT * FROM assessments WHERE assessment_type = 'pre_conference' LIMIT 5");
      results.assessments = {
        count: assessmentsData.length,
        data: assessmentsData
      };
      console.log(`✅ Found ${assessmentsData.length} pre_conference assessments`);
    } catch (err) {
      results.assessments = { error: err.message };
      console.log(`❌ Error checking assessments: ${err.message}`);
    }
    
    res.json({
      message: 'Penilaian tables test completed',
      results
    });
  } catch (err) {
    console.error('❌ Error testing penilaian tables:', err);
    res.status(500).json({ 
      message: 'Failed to test penilaian tables.', 
      error: err.message 
    });
  }
});

// Test manual insertion into penilaian_pre_conference
app.post('/api/test/insert-penilaian', async (req, res) => {
  try {
    console.log('🧪 Testing manual insertion into penilaian_pre_conference...');
    
    // First create a test assessment
    const [assessmentResult] = await pool.query(`
      INSERT INTO assessments (
        submission_id, assessed_user_id, assessor_user_id, 
        assessment_type, score, comments, assessment_date, 
        academic_year, semester
      ) VALUES (NULL, 'U00001', 'U00007', 'pre_conference', NULL, 'Test comment', NOW(), 2025, 'Ganjil')
    `);
    
    const assessmentId = assessmentResult.insertId;
    console.log(`✅ Test assessment created: ${assessmentId}`);
    
    // Try to insert into penilaian_pre_conference
    try {
      const [penilaianResult] = await pool.query(`
        INSERT INTO penilaian_pre_conference (
          assessment_id, aspect_precon_1, aspect_precon_2, aspect_precon_3, 
          aspect_precon_4, aspect_precon_5
        ) VALUES (?, 3, 4, 5, 3, 4)
      `, [assessmentId]);
      
      console.log(`✅ Manual insertion successful:`, penilaianResult);
      
      // Verify the insertion
      const [verifyData] = await pool.query(`
        SELECT * FROM penilaian_pre_conference WHERE assessment_id = ?
      `, [assessmentId]);
      
      res.json({
        message: 'Manual insertion test completed',
        assessment_id: assessmentId,
        penilaian_result: penilaianResult,
        verification: verifyData
      });
      
    } catch (insertError) {
      console.error(`❌ Manual insertion failed:`, insertError);
      res.status(500).json({
        message: 'Manual insertion failed',
        error: insertError.message,
        code: insertError.code
      });
    }
    
  } catch (err) {
    console.error('❌ Error in manual insertion test:', err);
    res.status(500).json({ 
      message: 'Failed to test manual insertion.', 
      error: err.message 
    });
  }
});

// Test frontend data format
app.post('/api/test/frontend-data', async (req, res) => {
  try {
    console.log('🧪 Testing frontend data format...');
    console.log('📥 Received data:', req.body);
    
    const {
      assessed_user_id,
      assessor_user_id,
      assessment_type,
      comments,
      academic_year,
      semester,
      assessment_data
    } = req.body;
    
    console.log('📋 Parsed data:', {
      assessed_user_id,
      assessor_user_id,
      assessment_type,
      comments,
      academic_year,
      semester,
      assessment_data
    });
    
    if (assessment_data) {
      console.log('📊 Assessment data details:', {
        has_data: !!assessment_data,
        keys: Object.keys(assessment_data),
        values: assessment_data
      });
    }
    
    res.json({
      message: 'Frontend data test completed',
      received_data: req.body,
      parsed_data: {
        assessed_user_id,
        assessor_user_id,
        assessment_type,
        comments,
        academic_year,
        semester,
        assessment_data
      }
    });
    
  } catch (err) {
    console.error('❌ Error testing frontend data:', err);
    res.status(500).json({ 
      message: 'Failed to test frontend data.', 
      error: err.message 
    });
  }
});

// Test all assessment types
app.get('/api/test/all-assessment-types', async (req, res) => {
  try {
    console.log('🧪 Testing all assessment types...');
    
    const assessmentTypes = [
      'pre_conference',
      'post_conference', 
      'laporan_pendahuluan',
      'asuhan_keperawatan',
      'analisa_sintesa',
      'sikap_mahasiswa',
      'keterampilan_prosedural_klinik_dops',
      'ujian_klinik',
      'telaah_artikel_jurnal',
      'case_report'
    ];
    
    const results = {};
    
    for (const type of assessmentTypes) {
      try {
        // Check if table exists
        const tableName = getTableNameForAssessmentType(type);
        const [tableExists] = await pool.query(`SHOW TABLES LIKE '${tableName}'`);
        
        if (tableExists.length > 0) {
          // Check if there are any records
          const [records] = await pool.query(`SELECT COUNT(*) as count FROM ${tableName}`);
          const [assessments] = await pool.query(`SELECT COUNT(*) as count FROM assessments WHERE assessment_type = ?`, [type]);
          
          results[type] = {
            exists: true,
            table: tableName,
            penilaian_records: records[0].count,
            assessment_records: assessments[0].count
          };
          console.log(`✅ ${type}: Table ${tableName} exists with ${records[0].count} records`);
        } else {
          results[type] = {
            exists: false,
            table: tableName,
            error: 'Table does not exist'
          };
          console.log(`❌ ${type}: Table ${tableName} does not exist`);
        }
      } catch (err) {
        results[type] = {
          exists: false,
          error: err.message
        };
        console.log(`❌ ${type}: Error - ${err.message}`);
      }
    }
    
    res.json({
      message: 'All assessment types test completed',
      results
    });
    
  } catch (err) {
    console.error('❌ Error testing all assessment types:', err);
    res.status(500).json({ 
      message: 'Failed to test all assessment types.', 
      error: err.message 
    });
  }
});

function getTableNameForAssessmentType(type) {
  const tableMap = {
    'pre_conference': 'penilaian_pre_conference',
    'post_conference': 'penilaian_post_conference',
    'laporan_pendahuluan': 'penilaian_laporan_pendahuluan',
    'asuhan_keperawatan': 'penilaian_laporan',
    'analisa_sintesa': 'penilaian_laporan',
    'sikap_mahasiswa': 'penilaian_sikap_mahasiswa',
    'keterampilan_prosedural_klinik_dops': 'keterampilan_prosedural_klinik',
    'ujian_klinik': 'penilaian_ujian_klinik',
    'telaah_artikel_jurnal': 'telaah_artikel_jurnal',
    'case_report': 'penilaian_case_report'
  };
  return tableMap[type] || 'unknown';
}

// Test table structure and constraints
app.get('/api/test/table-structure', async (req, res) => {
  try {
    console.log('🔍 Testing table structure...');
    
    // Check assessments table structure
    const [assessmentsStructure] = await pool.query("DESCRIBE assessments");
    console.log('📋 Assessments table structure:', assessmentsStructure);
    
    // Check penilaian_pre_conference table structure
    const [penilaianStructure] = await pool.query("DESCRIBE penilaian_pre_conference");
    console.log('📋 Penilaian_pre_conference table structure:', penilaianStructure);
    
    // Check foreign key constraints
    const [constraints] = await pool.query(`
      SELECT 
        CONSTRAINT_NAME,
        COLUMN_NAME,
        REFERENCED_TABLE_NAME,
        REFERENCED_COLUMN_NAME
      FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'penilaian_pre_conference'
      AND REFERENCED_TABLE_NAME IS NOT NULL
    `);
    console.log('🔗 Foreign key constraints:', constraints);
    
    // Check if there are any existing records
    const [assessmentsCount] = await pool.query("SELECT COUNT(*) as count FROM assessments WHERE assessment_type = 'pre_conference'");
    const [penilaianCount] = await pool.query("SELECT COUNT(*) as count FROM penilaian_pre_conference");
    
    console.log(`📊 Records count - Assessments: ${assessmentsCount[0].count}, Penilaian: ${penilaianCount[0].count}`);
    
    res.json({
      message: 'Table structure test completed',
      assessments_structure: assessmentsStructure,
      penilaian_structure: penilaianStructure,
      constraints: constraints,
      counts: {
        assessments: assessmentsCount[0].count,
        penilaian: penilaianCount[0].count
      }
    });
    
  } catch (err) {
    console.error('❌ Error testing table structure:', err);
    res.status(500).json({ 
      message: 'Failed to test table structure.', 
      error: err.message 
    });
  }
});

// Get assessment statistics
app.get('/api/assessments/statistics', async (req, res) => {
  try {
    console.log('📊 Fetching assessment statistics...');
    
    // Get total assessments
    const [totalAssessments] = await pool.query('SELECT COUNT(*) as total FROM assessments');
    
    // Get assessments by type
    const [assessmentsByType] = await pool.query(`
      SELECT assessment_type, COUNT(*) as count, AVG(score) as avg_score
      FROM assessments 
      GROUP BY assessment_type
    `);
    
    // Get assessments by academic year
    const [assessmentsByYear] = await pool.query(`
      SELECT academic_year, COUNT(*) as count, AVG(score) as avg_score
      FROM assessments 
      GROUP BY academic_year
      ORDER BY academic_year DESC
    `);
    
    // Get assessments by semester
    const [assessmentsBySemester] = await pool.query(`
      SELECT semester, COUNT(*) as count, AVG(score) as avg_score
      FROM assessments 
      GROUP BY semester
    `);
    
    // Get recent assessments (last 30 days)
    const [recentAssessments] = await pool.query(`
      SELECT COUNT(*) as count
      FROM assessments 
      WHERE assessment_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    `);
    
    const statistics = {
      total: totalAssessments[0].total,
      byType: assessmentsByType,
      byYear: assessmentsByYear,
      bySemester: assessmentsBySemester,
      recent: recentAssessments[0].count
    };
    
    console.log('✅ Assessment statistics:', statistics);
    res.json(statistics);
  } catch (err) {
    console.error('❌ Error fetching assessment statistics:', err);
    res.status(500).json({ message: 'Failed to fetch assessment statistics.' });
  }
});

// Get all conferences
app.get('/api/conferences', async (req, res) => {
  try {
    console.log('📅 Fetching all conferences...');
    
    // First check if conference table exists
    const [tables] = await pool.query("SHOW TABLES LIKE 'conference'");
    if (tables.length === 0) {
      console.log('⚠️ Conference table does not exist, returning empty array');
      return res.json([]);
    }
    
    const [conferences] = await pool.query(`
      SELECT * FROM conference
      ORDER BY scheduled_time ASC
    `);
    console.log(`✅ Found ${conferences.length} conferences`);
    res.json(conferences);
  } catch (err) {
    console.error('❌ Error fetching conferences:', err);
    res.status(500).json({ message: 'Failed to fetch conferences.' });
  }
});

// Create new conference
app.post('/api/conferences', authenticateJWT, async (req, res) => {
  try {
    const { platform, title, link, description, scheduled_time } = req.body;
    
    // Check if user is not mahasiswa
    if (req.user.role === 'mahasiswa') {
      return res.status(403).json({ message: 'Access denied: Mahasiswa cannot create conferences.' });
    }
    
    // Check if conference table exists
    const [tables] = await pool.query("SHOW TABLES LIKE 'conference'");
    if (tables.length === 0) {
      return res.status(500).json({ message: 'Conference table does not exist. Please run database setup first.' });
    }
    
    // Generate conference ID
    const [lastConference] = await pool.query('SELECT conference_id FROM conference ORDER BY conference_id DESC LIMIT 1');
    let nextId = 'C00001';
    if (lastConference.length > 0) {
      const lastId = lastConference[0].conference_id;
      const num = parseInt(lastId.substring(1)) + 1;
      nextId = `C${num.toString().padStart(5, '0')}`;
    }
    
    // Insert new conference
        await pool.query(`
      INSERT INTO conference (conference_id, platform, title, link, description, scheduled_time)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [nextId, platform, title, link, description, scheduled_time]);
    
    console.log(`✅ Conference created: ${nextId}`);
    res.status(201).json({ message: 'Conference created successfully.', conference_id: nextId });
  } catch (err) {
    console.error('❌ Error creating conference:', err);
    res.status(500).json({ message: 'Failed to create conference.' });
  }
});

// Update conference
app.put('/api/conferences/:conferenceId', authenticateJWT, async (req, res) => {
  try {
    const { conferenceId } = req.params;
    const { platform, title, link, description, scheduled_time } = req.body;
    
    // Check if user is not mahasiswa
    if (req.user.role === 'mahasiswa') {
      return res.status(403).json({ message: 'Access denied: Mahasiswa cannot update conferences.' });
    }
    
    // Check if conference exists
    const [existing] = await pool.query('SELECT * FROM conference WHERE conference_id = ?', [conferenceId]);
    if (existing.length === 0) {
      return res.status(404).json({ message: 'Conference not found.' });
    }
    
    // Update conference
        await pool.query(`
      UPDATE conference 
      SET platform = ?, title = ?, link = ?, description = ?, scheduled_time = ?
      WHERE conference_id = ?
    `, [platform, title, link, description, scheduled_time, conferenceId]);
    
    console.log(`✅ Conference updated: ${conferenceId}`);
    res.json({ message: 'Conference updated successfully.' });
  } catch (err) {
    console.error('❌ Error updating conference:', err);
    res.status(500).json({ message: 'Failed to update conference.' });
  }
});

// Delete conference
app.delete('/api/conferences/:conferenceId', authenticateJWT, async (req, res) => {
  try {
    const { conferenceId } = req.params;
    
    // Check if user is not mahasiswa
    if (req.user.role === 'mahasiswa') {
      return res.status(403).json({ message: 'Access denied: Mahasiswa cannot delete conferences.' });
    }
    
    // Check if conference exists
    const [existing] = await pool.query('SELECT * FROM conference WHERE conference_id = ?', [conferenceId]);
    if (existing.length === 0) {
      return res.status(404).json({ message: 'Conference not found.' });
    }
    
    // Delete conference
    await pool.query('DELETE FROM conference WHERE conference_id = ?', [conferenceId]);
    
    console.log(`✅ Conference deleted: ${conferenceId}`);
    res.json({ message: 'Conference deleted successfully.' });
  } catch (err) {
    console.error('❌ Error deleting conference:', err);
    res.status(500).json({ message: 'Failed to delete conference.' });
  }
});

// Create conference table if it doesn't exist
app.post('/api/setup/conference-table', async (req, res) => {
  try {
    console.log('🔧 Setting up conference table...');
    
    // Create conference table
        await pool.query(`
      CREATE TABLE IF NOT EXISTS conference (
        conference_id VARCHAR(10) PRIMARY KEY,
        platform ENUM('Zoom', 'Google Meet', 'WhatsApp', 'Discord') NOT NULL,
        title VARCHAR(255) NOT NULL,
        link VARCHAR(255) NOT NULL,
        description TEXT,
        scheduled_time DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ Conference table setup completed');
    res.status(201).json({ message: 'Conference table setup completed' });
  } catch (err) {
    console.error('❌ Error setting up conference table:', err);
    res.status(500).json({ message: 'Failed to set up conference table.', error: err.message });
  }
});

// Add this at the end of the file to start the server if not present
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API available at http://localhost:${PORT}/api`);
});