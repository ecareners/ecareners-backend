const mysql = require('mysql2/promise');
require('dotenv').config();

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'ecareners',
  port: process.env.DB_PORT || 3306
};

async function testDatabase() {
  console.log('🔍 Testing database connection...');
  console.log('📊 Database config:', {
    host: dbConfig.host,
    user: dbConfig.user,
    database: dbConfig.database,
    port: dbConfig.port
  });

  try {
    // Test connection
    const pool = mysql.createPool(dbConfig);
    const connection = await pool.getConnection();
    console.log('✅ Database connection successful!');

    // Test tables
    console.log('\n🔍 Checking tables...');
    
    // Check user table
    const [users] = await connection.execute('SELECT COUNT(*) as count FROM user');
    console.log(`👥 Users table: ${users[0].count} records`);

    // Check assignments table
    const [assignments] = await connection.execute('SELECT COUNT(*) as count FROM assignments');
    console.log(`📚 Assignments table: ${assignments[0].count} records`);

    // Check submission table
    const [submissions] = await connection.execute('SELECT COUNT(*) as count FROM submission');
    console.log(`📝 Submissions table: ${submissions[0].count} records`);

    // Check specific user
    const [userRows] = await connection.execute('SELECT * FROM user WHERE user_id = ?', ['U00002']);
    if (userRows.length > 0) {
      console.log(`✅ User U00002 found: ${userRows[0].name}`);
    } else {
      console.log('❌ User U00002 not found');
    }

    // Check specific assignment
    const [assignmentRows] = await connection.execute('SELECT * FROM assignments WHERE assignment_id = ?', [3]);
    if (assignmentRows.length > 0) {
      console.log(`✅ Assignment 3 found: ${assignmentRows[0].title}`);
    } else {
      console.log('❌ Assignment 3 not found');
    }

    // Check submission for U00002 and assignment 3
    const [submissionRows] = await connection.execute(
      'SELECT * FROM submission WHERE user_id = ? AND assignment_id = ?', 
      ['U00002', 3]
    );
    if (submissionRows.length > 0) {
      console.log(`✅ Submission found for U00002 and assignment 3`);
    } else {
      console.log('❌ No submission found for U00002 and assignment 3');
    }

    connection.release();
    console.log('\n✅ Database test completed successfully!');
    
  } catch (error) {
    console.error('❌ Database test failed:', error.message);
    console.error('Full error:', error);
  }
}

testDatabase(); 