import { Router } from 'express';
import reportRoutes from './reportRoutes.js';
import analyzeRoutes from './analyzeRoutes.js';

const router = Router();

router.get('/', (req, res) => {
  res.json({ message: 'Memory Trace Backend Running' });
});

router.use('/reports', reportRoutes);
router.use('/analyze', analyzeRoutes);

export default router;
