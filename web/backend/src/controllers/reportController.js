import * as reportService from '../services/reportService.js';

export const getReports = async (req, res) => {
  try {
    const reports = await reportService.fetchAllReports();
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve reports', details: err.message });
  }
};

export const getSingleReport = async (req, res) => {
  try {
    const report = await reportService.fetchReportByName(req.params.test_name);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read report file', details: err.message });
  }
};
