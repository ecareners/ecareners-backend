const fetch = require('node-fetch');

const API_BASE_URL = 'http://localhost:5000';

async function testCaseReport() {
  console.log('🧪 Testing Case Report Assessment...\n');

  const testData = {
    assessed_user_id: 'U00001',
    assessor_user_id: 'U00007',
    assessment_type: 'case_report',
    comments: 'Test Case Report assessment',
    academic_year: 2025,
    semester: 'Ganjil',
    assessment_data: {
      aspek_casport_1: 4,
      aspek_casport_2: 3,
      aspek_casport_3: 4,
      aspek_casport_4: 3
    }
  };

  console.log('📤 Sending data:', testData);
  
  try {
    const response = await fetch(`${API_BASE_URL}/api/assessments/detailed`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(testData),
    });

    if (response.ok) {
      const result = await response.json();
      console.log('✅ Case Report - SUCCESS');
      console.log('   Assessment ID:', result.assessment_id);
      console.log('   Response:', result);
    } else {
      const error = await response.json();
      console.log('❌ Case Report - FAILED');
      console.log('   Error:', error);
    }
  } catch (error) {
    console.log('❌ Case Report - ERROR');
    console.log('   Error:', error.message);
  }
}

testCaseReport().catch(console.error); 