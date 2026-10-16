import express from 'express';
import { listAllUsers, exportUsers } from './admin';

const app = express();
~>app.get("/api/admin/users", listAllUsers);
~>app.get(`/admin/export`, exportUsers)
