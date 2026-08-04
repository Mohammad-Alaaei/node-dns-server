import { authenticate } from './connection.mjs';
import './models/index.mjs';

export async function createSchema() {
    await authenticate();
}