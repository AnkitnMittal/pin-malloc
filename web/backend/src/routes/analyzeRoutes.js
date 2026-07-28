import { Router } from 'express';
import { analyzeCode } from '../controllers/analyzeController.js';

const router = Router();

router.post('/', analyzeCode);

export default router;
