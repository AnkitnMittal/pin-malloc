import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { REPORTS_DIR } from '../config/paths.js';

export const fetchAllReports = async () => {
  if (!existsSync(REPORTS_DIR)) {
    return [];
  }

  const files = await fs.readdir(REPORTS_DIR);
  const jsonFiles = files.filter((file) => file.endsWith('.json'));

  return Promise.all(
    jsonFiles.map(async (file) => {
      const filePath = path.join(REPORTS_DIR, file);
      const rawData = await fs.readFile(filePath, 'utf-8');
      return {
        test_name: path.parse(file).name,
        data: JSON.parse(rawData),
      };
    }),
  );
};

export const fetchReportByName = async (testName) => {
  const filePath = path.join(REPORTS_DIR, `${testName}.json`);

  if (!existsSync(filePath)) {
    return null;
  }

  const rawData = await fs.readFile(filePath, 'utf-8');
  return JSON.parse(rawData);
};
