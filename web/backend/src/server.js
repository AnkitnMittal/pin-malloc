import app from './app.js';

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`Memory Trace Express Server running on http://localhost:${PORT}`);
});
