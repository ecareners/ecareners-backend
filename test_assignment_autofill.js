const API_BASE_URL = 'http://localhost:3000';

// Test assignment auto-fill for all assignment-based assessment types
const testAssignmentAutoFill = async () => {
  console.log('🧪 Testing Assignment Auto-Fill Functionality\n');

  const testCases = [
    {
      assessmentType: 'laporan_pendahuluan',
      expectedAssignmentId: 1,
      description: 'Laporan Pendahuluan Assessment'
    },
    {
      assessmentType: 'asuhan_keperawatan', // changed from 'asuhan_keperawatan_analisa_sintesa'
      expectedAssignmentId: 2,
      description: 'Asuhan Keperawatan Assessment'
    },
    {
      assessmentType: 'telaah_artikel_jurnal',
      expectedAssignmentId: 5,
      description: 'Telaah Artikel Jurnal Assessment'
    },
    {
      assessmentType: 'case_report',
      expectedAssignmentId: 3,
      description: 'Case Report Assessment'
    }
  ];

  for (const testCase of testCases) {
    console.log(`📋 Testing: ${testCase.description}`);
    console.log(`   Assessment Type: ${testCase.assessmentType}`);
    console.log(`   Expected Assignment ID: ${testCase.expectedAssignmentId}`);

    try {
      // Test 1: Fetch assignment data
      const assignmentResponse = await fetch(`${API_BASE_URL}/api/assignments/${testCase.expectedAssignmentId}`);
      if (assignmentResponse.ok) {
        const assignmentData = await assignmentResponse.json();
        console.log(`   ✅ Assignment data fetched successfully`);
        console.log(`   📄 Assignment Title: ${assignmentData.title}`);
        console.log(`   📄 Assignment Type: ${assignmentData.assignment_type}`);
        console.log(`   📄 Assignment ID: ${assignmentData.assignment_id}`);
      } else {
        console.log(`   ❌ Failed to fetch assignment data`);
      }

      // Test 2: Test assessment submission with auto-filled assignment ID
      const testAssessmentData = {
        assessed_user_id: 'U00001',
        assessor_user_id: 'U00002',
        assessment_type: testCase.assessmentType,
        assignment_id: testCase.expectedAssignmentId,
        comments: `Test assessment for ${testCase.description}`,
        academic_year: new Date().getFullYear(),
        semester: 'Ganjil',
        assessment_data: {}
      };

      // Add sample assessment data based on type
      switch (testCase.assessmentType) {
        case 'laporan_pendahuluan':
          testAssessmentData.assessment_data = {
            aspect_lappen_1: 85,
            aspect_lappen_2: 90,
            aspect_lappen_3: 80,
            aspect_lappen_4: 88
          };
          break;
        case 'asuhan_keperawatan':
          testAssessmentData.assessment_data = {
            aspect_laporan_1: 3,
            aspect_laporan_2: 4,
            aspect_laporan_3: 3,
            aspect_laporan_4: 4,
            aspect_laporan_5: 3,
            aspect_laporan_6: 4,
            aspect_laporan_7: 3,
            aspect_laporan_8: 4,
            aspect_laporan_9: 3,
            aspect_laporan_10: 4
          };
          break;
        case 'telaah_artikel_jurnal':
          testAssessmentData.assessment_data = {
            aspect_jurnal_1: 85,
            aspect_jurnal_2: 90,
            aspect_jurnal_3: 88,
            aspect_jurnal_4: 92,
            aspect_jurnal_5: 87
          };
          break;
        case 'case_report':
          testAssessmentData.assessment_data = {
            aspek_casport_1: 88,
            aspek_casport_2: 85,
            aspek_casport_3: 90,
            aspek_casport_4: 87
          };
          break;
      }

      console.log(`   📤 Sending test assessment with assignment_id: ${testCase.expectedAssignmentId}`);
      
      const assessmentResponse = await fetch(`${API_BASE_URL}/api/assessments/detailed`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(testAssessmentData),
      });

      if (assessmentResponse.ok) {
        const result = await assessmentResponse.json();
        console.log(`   ✅ Assessment submitted successfully`);
        console.log(`   📄 Assessment ID: ${result.assessment_id}`);
        console.log(`   📄 Assignment ID used: ${testCase.expectedAssignmentId}`);
      } else {
        const errorData = await assessmentResponse.json();
        console.log(`   ❌ Assessment submission failed: ${errorData.message}`);
      }

    } catch (error) {
      console.log(`   ❌ Error: ${error.message}`);
    }

    console.log(''); // Empty line for readability
  }

  console.log('🏁 Assignment auto-fill testing completed!');
};

// Run the test
testAssignmentAutoFill().catch(console.error); 