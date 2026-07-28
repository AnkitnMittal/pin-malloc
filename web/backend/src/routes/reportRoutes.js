import { Router } from 'express';
import { getReports, getSingleReport } from '../controllers/reportController.js';

const router = Router();

router.get('/', getReports);
router.get('/:test_name', getSingleReport);

export default router;
