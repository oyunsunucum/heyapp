const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

// Load env vars
dotenv.config();

const app = express();
const prisma = new PrismaClient();

// Middleware
app.use(cors());
app.use(express.json());

const path = require('path');
app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'privacy-policy.html'));
});

// S3 (Cloudflare R2) Client config
const s3Client = new S3Client({
  region: 'auto',
  endpoint: process.env.R2_ENDPOINT,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

// -- MIDDLEWARES --
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Erişim engellendi.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Geçersiz token.' });
    req.user = user;
    next();
  });
};

// --- AUTH ROUTALARI ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check existing
    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ email }, { username }] }
    });
    if (existingUser) {
      return res.status(400).json({ error: 'Kullanıcı adı veya e-posta zaten mevcut.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = await prisma.user.create({
      data: { username, email, passwordHash },
    });

    const token = jwt.sign({ id: newUser.id, username: newUser.username, isPremium: newUser.isPremium }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: newUser.id, username: newUser.username, email: newUser.email, isPremium: newUser.isPremium } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(400).json({ error: 'Geçersiz şifre.' });

    const token = jwt.sign({ id: user.id, username: user.username, isPremium: user.isPremium }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, isPremium: user.isPremium } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    res.json({ id: user.id, username: user.username, email: user.email, isPremium: user.isPremium });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { OAuth2Client } = require('google-auth-library');
    const WEB_CLIENT_ID = '447637886445-hc0ueb3uhb32jbopaka17dpg7ressutr.apps.googleusercontent.com';
    const ANDROID_CLIENT_ID = '447637886445-gqblb65vc1045m51ncne3qmpvpnol5ri.apps.googleusercontent.com';
    const googleClient = new OAuth2Client(WEB_CLIENT_ID);
    const { idToken } = req.body;
    
    if (!idToken) {
      return res.status(400).json({ error: 'idToken gerekli.' });
    }
    
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: [WEB_CLIENT_ID, ANDROID_CLIENT_ID],
    });
    const payload = ticket.getPayload();
    const { email, name } = payload;
    
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      user = await prisma.user.create({
        data: {
          email,
          username: name.replace(/\s+/g, '').toLowerCase() + Math.random().toString(36).substring(7),
          passwordHash: '', 
        }
      });
    }

    const token = jwt.sign({ id: user.id, username: user.username, isPremium: user.isPremium }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, isPremium: user.isPremium } });
  } catch (err) {
    res.status(401).json({ error: 'Geçersiz Google Token: ' + err.message });
  }
});

// --- VIDEO ROUTALARI ---
app.get('/api/videos/upload-url', authenticateToken, async (req, res) => {
  try {
    const { filename, contentType } = req.query;
    if (!filename || !contentType) {
      return res.status(400).json({ error: 'filename ve contentType parametreleri gerekli.' });
    }

    // Refresh user state from db to check premium status securely
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    
    // Limits check: 
    // - Free users: Expires in 15 mins (ideal for ~3 min video uploads).
    // - Premium users: Expires in 3 hours.
    const expiresInSeconds = user.isPremium ? 3 * 60 * 60 : 15 * 60; // 3 hours vs 15 mins

    // Cleaned filename
    const safeFilename = filename.replace(/[^a-zA-Z0-9.\-_]/g, '');
    const key = `videos/${Date.now()}-${req.user.id}-${safeFilename}`;
    
    const command = new PutObjectCommand({
      Bucket: process.env.R2_BUCKET_NAME,
      Key: key,
      ContentType: contentType,
    });

    const url = await getSignedUrl(s3Client, command, { expiresIn: expiresInSeconds });

    // The key needs to be saved when user confirms upload, so we send it back.
    res.json({ url, key, publicUrl: `${process.env.R2_PUBLIC_URL}/${key}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload URL oluşturulamadı.' });
  }
});

app.post('/api/videos', authenticateToken, async (req, res) => {
  try {
    const { url, description } = req.body; // url usually would be the R2 'publicUrl' or 'key'
    const newVideo = await prisma.video.create({
      data: {
        url,
        description,
        authorId: req.user.id
      },
      include: { author: { select: { id: true, username: true } } }
    });
    res.json(newVideo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// List videos (Feed endpoint)
app.get('/api/videos/feed', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    
    const videos = await prisma.video.findMany({
      take: limit,
      skip: (page - 1) * limit,
      orderBy: { createdAt: 'desc' },
      include: { 
        author: { select: { id: true, username: true, isPremium: true } },
        _count: { select: { likes: true, comments: true } }
      }
    });

    // Determine current user if auth header is provided to embed like statuses
    let userId = null;
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      const token = authHeader.split(' ')[1];
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.id;
      } catch (e) {
        // invalid token, ignore
      }
    }

    let modifiedVideos = videos;
    if (userId) {
      // Find all likes by this user for the current videos
      const videoIds = videos.map(v => v.id);
      const userLikes = await prisma.like.findMany({
        where: { userId, videoId: { in: videoIds } }
      });
      const likedVideoIds = new Set(userLikes.map(l => l.videoId));

      modifiedVideos = videos.map(v => ({
        ...v,
        isLikedByMe: likedVideoIds.has(v.id)
      }));
    }

    res.json(modifiedVideos);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- SOCIAL ROUTALARI ---
app.post('/api/videos/:id/like', authenticateToken, async (req, res) => {
  try {
    const videoId = req.params.id;
    const existingLike = await prisma.like.findFirst({
      where: { userId: req.user.id, videoId }
    });

    if (existingLike) {
      await prisma.like.delete({ where: { id: existingLike.id } });
      return res.json({ liked: false });
    } else {
      await prisma.like.create({ data: { userId: req.user.id, videoId } });
      return res.json({ liked: true });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/videos/:id/comment', authenticateToken, async (req, res) => {
  try {
    const videoId = req.params.id;
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Yorum içeriği boş olamaz.' });

    const newComment = await prisma.comment.create({
      data: {
        content,
        userId: req.user.id,
        videoId
      },
      include: { user: { select: { id: true, username: true } } }
    });
    res.json(newComment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const videoId = req.params.id;
    const comments = await prisma.comment.findMany({
      where: { videoId },
      orderBy: { createdAt: 'desc' },
      include: { user: { select: { id: true, username: true } } }
    });
    res.json(comments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const followingId = req.params.id;
    const followerId = req.user.id;

    if (followerId === followingId) {
      return res.status(400).json({ error: 'Kendinizi takip edemezsiniz.' });
    }

    const existingFollow = await prisma.follow.findFirst({
      where: { followerId, followingId }
    });

    if (existingFollow) {
      await prisma.follow.delete({ where: { id: existingFollow.id } });
      return res.json({ following: false });
    } else {
      await prisma.follow.create({ data: { followerId, followingId } });
      return res.json({ following: true });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/users/:id/profile', authenticateToken, async (req, res) => {
  try {
    const profileId = req.params.id;
    
    const profile = await prisma.user.findUnique({
      where: { id: profileId },
      select: {
        id: true,
        username: true,
        isPremium: true,
        _count: {
          select: { followers: true, following: true, videos: true }
        }
      }
    });

    if (!profile) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

    const isFollowing = await prisma.follow.findFirst({
      where: { followerId: req.user.id, followingId: profileId }
    });

    const videos = await prisma.video.findMany({
      where: { authorId: profileId },
      orderBy: { createdAt: 'desc' }
    });

    res.json({ ...profile, isFollowingByMe: !!isFollowing, videos });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// START SERVER
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend ${PORT} portunda çalışıyor...`);
});

// Vercel serverless export
module.exports = app;
