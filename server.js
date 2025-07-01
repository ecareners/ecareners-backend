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
app.use(cors());
app.use(express.json());

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'ecareners',
  port: process.env.DB_PORT || 3306
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

    // Clean up temporary file
    fs.unlinkSync(filePath);

    console.log(`✅ File uploaded successfully. File ID: ${response.data.id}`);

    res.json({ 
      success: true,
      fileId: response.data.id,
      fileName: fileName,
      message: 'File uploaded to Google Drive successfully'
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
      ORDER BY a.assessment_date DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching assessments:', err);
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
    
    // Get all students
    console.log('📚 Fetching all students...');
    const [students] = await pool.query(`
      SELECT user_id, name, email, prodi 
      FROM user 
      WHERE role = 'student' OR role = 'mahasiswa'
      ORDER BY name
    `);
    console.log(`✅ Found ${students.length} students`);
    
    // Get submissions for this assignment
    console.log(`📝 Fetching submissions for assignment ${assignmentId}...`);
    const [submissions] = await pool.query(`
      SELECT s.*, u.name as user_name, u.email, u.prodi
      FROM submission s
      JOIN user u ON s.user_id = u.user_id
      WHERE s.assignment_id = ?
      ORDER BY s.submitted_at DESC
    `, [assignmentId]);
    console.log(`✅ Found ${submissions.length} submissions`);
    
    // Get assessments for this assignment
    console.log(`⭐ Fetching assessments for assignment ${assignmentId}...`);
    const [assessments] = await pool.query(`
      SELECT a.*, s.assignment_id
      FROM assessments a
      JOIN submission s ON a.submission_id = s.submission_id
      WHERE s.assignment_id = ?
    `, [assignmentId]);
    console.log(`✅ Found ${assessments.length} assessments`);
    
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
    res.status(500).json({ message: 'Failed to fetch students.' });
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
    
    // Check if assessment already exists
    const [existing] = await pool.query(`
      SELECT assessment_id FROM assessments 
      WHERE submission_id = ? AND assessed_user_id = ? AND assessor_user_id = ?
    `, [submission_id, assessed_user_id, assessor_user_id]);
    
    if (existing.length > 0) {
      // Update existing assessment
      await pool.query(`
        UPDATE assessments 
        SET score = ?, comments = ?, assessment_date = NOW()
        WHERE assessment_id = ?
      `, [score, comments, existing[0].assessment_id]);
      
      res.json({ message: 'Assessment updated successfully.' });
    } else {
      // Create new assessment
      await pool.query(`
        INSERT INTO assessments (
          submission_id, assessed_user_id, assessor_user_id, 
          assessment_type, score, comments, assessment_date, 
          academic_year, semester
        ) VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, ?)
      `, [submission_id, assessed_user_id, assessor_user_id, 
          assessment_type, score, comments, academic_year, semester]);
      
      res.status(201).json({ message: 'Assessment created successfully.' });
    }
  } catch (err) {
    console.error('Error creating/updating assessment:', err);
    res.status(500).json({ message: 'Failed to create/update assessment.' });
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

// Get students for assessment type (without assignment)
app.get('/api/assessment-types/:assessmentType/students', async (req, res) => {
  try {
    const { assessmentType } = req.params;
    console.log(`🔍 Fetching students for assessment type: ${assessmentType}`);
    
    // Get all students
    console.log('📚 Fetching all students...');
    const [students] = await pool.query(`
      SELECT user_id, name, email, prodi 
      FROM user 
      WHERE role = 'student' OR role = 'mahasiswa'
      ORDER BY name
    `);
    console.log(`✅ Found ${students.length} students`);
    
    // Get existing assessments for this type
    console.log(`⭐ Fetching existing assessments for type ${assessmentType}...`);
    const [assessments] = await pool.query(`
      SELECT a.*, u.name as student_name, u.email, u.prodi
      FROM assessments a
      JOIN user u ON a.assessed_user_id = u.user_id
      WHERE a.assessment_type = ?
      ORDER BY a.assessment_date DESC
    `, [assessmentType]);
    console.log(`✅ Found ${assessments.length} existing assessments`);
    
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
    res.status(500).json({ message: 'Failed to fetch students for assessment type.' });
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
      
      res.json({ message: 'Assessment updated successfully.' });
    } else {
      // Create new assessment without submission
      await pool.query(`
        INSERT INTO assessments (
          submission_id, assessed_user_id, assessor_user_id, 
          assessment_type, score, comments, assessment_date, 
          academic_year, semester
        ) VALUES (NULL, ?, ?, ?, ?, ?, NOW(), ?, ?)
      `, [assessed_user_id, assessor_user_id, assessment_type, score, comments, academic_year, semester]);
      
      res.status(201).json({ message: 'Assessment created successfully.' });
    }
  } catch (err) {
    console.error('Error creating/updating direct assessment:', err);
    res.status(500).json({ message: 'Failed to create/update assessment.' });
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
    
    console.log(`✅ Found ${assessments.length} assessments for user ${userId}`);
    console.log('📊 Assessment details:', assessments);
    res.json(assessments);
  } catch (err) {
    console.error('❌ Error fetching user assessments:', err);
    console.error('❌ Error details:', err.message);
    console.error('❌ Error stack:', err.stack);
    res.status(500).json({ message: 'Failed to fetch user assessments.' });
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
    
    // Insert sample data
    await pool.query(`
      INSERT IGNORE INTO conference (conference_id, platform, title, link, description, scheduled_time) VALUES
      ('C00001', 'Zoom', 'Weekly Clinical Discussion', 'https://zoom.us/j/123456789', 'Weekly discussion about clinical cases and patient care approaches', '2024-02-20 14:00:00'),
      ('C00002', 'Google Meet', 'Nursing Assessment Review', 'https://meet.google.com/abc-defg-hij', 'Review session for nursing assessment techniques and documentation', '2024-02-22 10:00:00'),
      ('C00003', 'WhatsApp', 'Emergency Response Training', 'https://wa.me/1234567890', 'Training session on emergency response protocols and procedures', '2024-02-25 16:00:00'),
      ('C00004', 'Discord', 'Medical Ethics Discussion', 'https://discord.gg/medicalethics', 'Discussion about medical ethics and professional conduct', '2024-02-28 13:00:00'),
      ('C00005', 'Zoom', 'Patient Safety Workshop', 'https://zoom.us/j/987654321', 'Workshop focusing on patient safety protocols and best practices', '2024-03-01 09:00:00')
    `);
    
    console.log('✅ Conference table setup completed');
    res.json({ message: 'Conference table created successfully with sample data.' });
  } catch (err) {
    console.error('❌ Error setting up conference table:', err);
    res.status(500).json({ message: 'Failed to setup conference table.', error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API available at http://localhost:${PORT}/api`);
}); 