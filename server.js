const http = require('http');
const app = require('./app');
const connectDB = require('./config/database');
const { configureSockets } = require('./sockets');

const PORT = process.env.PORT || 4000;

// Connect to database
connectDB();

const server = http.createServer(app);
const io = require('socket.io')(server, {
  cors: { origin: 'http://localhost:5173', credentials: true },
  cors: { origin: 'https://realtime-chat-app-navy-ten.vercel.app', credentials: true }
});

// Configure sockets
configureSockets(io);

server.listen(PORT, () => {
  console.log(`✅ Chat application running on http://localhost:${PORT}`);
});