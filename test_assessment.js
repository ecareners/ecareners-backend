const fetch = require('node-fetch');

const API_BASE_URL = 'http://localhost:5000';

async function testAssessmentDetailed() {
  console.log('🧪 Testing Assessment Detailed Endpoint...\n');

  const testCases = [
    {
      name: 'Pre Conference',
      type: 'pre_conference',
      data: {
        aspect_precon_1: 4,
        aspect_precon_2: 3,
        aspect_precon_3: 4,
        aspect_precon_4: 3,
        aspect_precon_5: 4
      }
    },
    {
      name: 'Post Conference',
      type: 'post_conference',
      data: {
        aspect_postcon_1: 4,
        aspect_postcon_2: 3,
        aspect_postcon_3: 4,
        aspect_postcon_4: 3,
        aspect_postcon_5: 4
      }
    },
    {
      name: 'Sikap Mahasiswa',
      type: 'sikap_mahasiswa',
      data: {
        aspek_sikap_1: 3, aspek_sikap_2: 4, aspek_sikap_3: 3, aspek_sikap_4: 4, aspek_sikap_5: 3,
        aspek_sikap_6: 4, aspek_sikap_7: 3, aspek_sikap_8: 4, aspek_sikap_9: 3, aspek_sikap_10: 4,
        aspek_sikap_11: 3, aspek_sikap_12: 4, aspek_sikap_13: 3, aspek_sikap_14: 4, aspek_sikap_15: 3,
        aspek_sikap_16: 4, aspek_sikap_17: 3, aspek_sikap_18: 4, aspek_sikap_19: 3, aspek_sikap_20: 4
      }
    },
    {
      name: 'DOPS',
      type: 'keterampilan_prosedural_klinik_dops',
      data: {
        aspect_dops_1: 3, aspect_dops_2: 4, aspect_dops_3: 3, aspect_dops_4: 4, aspect_dops_5: 3,
        aspect_dops_6: 4, aspect_dops_7: 3, aspect_dops_8: 4, aspect_dops_9: 3, aspect_dops_10: 4,
        aspect_dops_11: 3, aspect_dops_12: 4, aspect_dops_13: 3, aspect_dops_14: 4, aspect_dops_15: 3, aspect_dops_16: 4
      }
    },
    {
      name: 'Ujian Klinik',
      type: 'ujian_klinik',
      data: {
        aspek_klinik_1: 3, aspek_klinik_2: 4, aspek_klinik_3: 3, aspek_klinik_4: 4, aspek_klinik_5a: 3, aspek_klinik_5b: 4,
        aspek_klinik_6: 3, aspek_klinik_7: 4, aspek_klinik_8: 3, aspek_klinik_9: 4, aspek_klinik_10: 3,
        aspek_klinik_11: 4, aspek_klinik_12: 3, aspek_klinik_13: 4, aspek_klinik_14: 3, aspek_klinik_15: 4,
        aspek_klinik_16: 3, aspek_klinik_17: 4, aspek_klinik_18: 3
      }
    },
    {
      name: 'Laporan Pendahuluan',
      type: 'laporan_pendahuluan',
      data: {
        aspect_lappen_1: 4,
        aspect_lappen_2: 3,
        aspect_lappen_3: 4,
        aspect_lappen_4: 3
      }
    },
    {
      name: 'Asuhan Keperawatan',
      type: 'asuhan_keperawatan',
      data: {
        aspect_laporan_1: 3, aspect_laporan_2: 4, aspect_laporan_3: 3, aspect_laporan_4: 4, aspect_laporan_5: 3,
        aspect_laporan_6: 4, aspect_laporan_7: 3, aspect_laporan_8: 4, aspect_laporan_9: 3, aspect_laporan_10: 4
      }
    },
    {
      name: 'Telaah Artikel Jurnal',
      type: 'telaah_artikel_jurnal',
      data: {
        aspect_jurnal_1: 4,
        aspect_jurnal_2: 3,
        aspect_jurnal_3: 4,
        aspect_jurnal_4: 3,
        aspect_jurnal_5: 4
      }
    },
    {
      name: 'Case Report',
      type: 'case_report',
      data: {
        aspek_casport_1: 4,
        aspek_casport_2: 3,
        aspek_casport_3: 4,
        aspek_casport_4: 3
      }
    }
  ];

  for (const testCase of testCases) {
    console.log(`📝 Testing ${testCase.name}...`);
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/assessments/detailed`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          assessed_user_id: 'U00001',
          assessor_user_id: 'U00007',
          assessment_type: testCase.type,
          comments: `Test ${testCase.name} assessment`,
          academic_year: 2025,
          semester: 'Ganjil',
          assessment_data: testCase.data
        }),
      });

      if (response.ok) {
        const result = await response.json();
        console.log(`✅ ${testCase.name} - SUCCESS`);
        console.log(`   Assessment ID: ${result.assessment_id}`);
        console.log(`   Score: ${result.score}`);
        console.log(`   Detailed data saved: ${result.detailed_data ? 'YES' : 'NO'}\n`);
      } else {
        const error = await response.json();
        console.log(`❌ ${testCase.name} - FAILED`);
        console.log(`   Error: ${error.message}\n`);
      }
    } catch (error) {
      console.log(`❌ ${testCase.name} - ERROR`);
      console.log(`   Error: ${error.message}\n`);
    }
  }

  console.log('🏁 Testing completed!');
}

// Run the test
testAssessmentDetailed().catch(console.error); 