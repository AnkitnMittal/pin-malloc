import { analyzeCppCode } from '../services/pinService.js';

export const analyzeCode = async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ success: false, runtime_error: 'No code provided' });
  }

  try {
    const result = await analyzeCppCode(code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, runtime_error: err.message });
  }
};
