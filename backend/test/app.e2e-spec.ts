/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma.service';

describe('App (e2e)', () => {
  let app: INestApplication<App>;
  let prismaService: PrismaService;
  let authToken: string;
  let testUsername: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());

    prismaService = app.get<PrismaService>(PrismaService);

    await app.init();
  });

  beforeEach(async () => {
    await prismaService.post.deleteMany();
    await prismaService.user.deleteMany();
    testUsername = `testuser_${Date.now()}`;
  });

  afterAll(async () => {
    await prismaService.post.deleteMany();
    await prismaService.user.deleteMany();
    await app.close();
  });

  describe('/ (GET)', () => {
    it('should return 404 for root endpoint', () => {
      return request(app.getHttpServer()).get('/').expect(404);
    });
  });

  describe('Auth Endpoints', () => {
    describe('/auth/register (POST)', () => {
      it('should register a new user successfully', async () => {
        const registerDto = {
          username: testUsername,
          password: 'password123',
        };

        const response = await request(app.getHttpServer())
          .post('/auth/register')
          .send(registerDto)
          .expect(201);

        expect(response.body).toHaveProperty('access_token');
        expect(response.body).toHaveProperty('refresh_token');
        expect(response.body.user).toEqual({
          username: testUsername,
        });
        expect(typeof response.body.access_token).toBe('string');
        expect(typeof response.body.refresh_token).toBe('string');
      });

      it('should fail with invalid data', async () => {
        const invalidData = {
          username: '',
          password: '123', // too short
        };

        await request(app.getHttpServer())
          .post('/auth/register')
          .send(invalidData)
          .expect(400);
      });

      it('should fail with duplicate username', async () => {
        const registerDto = {
          username: testUsername,
          password: 'password123',
        };

        // First registration
        await request(app.getHttpServer())
          .post('/auth/register')
          .send(registerDto)
          .expect(201);

        // Second registration with same username should fail
        await request(app.getHttpServer())
          .post('/auth/register')
          .send(registerDto)
          .expect(409);
      });
    });

    describe('/auth/login (POST)', () => {
      beforeEach(async () => {
        // Create a user for login tests
        await request(app.getHttpServer()).post('/auth/register').send({
          username: testUsername,
          password: 'password123',
        });
      });

      it('should login with valid credentials', async () => {
        const loginDto = {
          username: testUsername,
          password: 'password123',
        };

        const response = await request(app.getHttpServer())
          .post('/auth/login')
          .send(loginDto)
          .expect(201);

        expect(response.body).toHaveProperty('access_token');
        expect(response.body).toHaveProperty('refresh_token');
        expect(response.body.user).toEqual({
          username: testUsername,
        });
        expect(typeof response.body.access_token).toBe('string');
        expect(typeof response.body.refresh_token).toBe('string');

        authToken = response.body.access_token;
      });

      it('should fail with invalid credentials', async () => {
        const loginDto = {
          username: testUsername,
          password: 'wrongpassword',
        };

        await request(app.getHttpServer())
          .post('/auth/login')
          .send(loginDto)
          .expect(401);
      });

      it('should fail with non-existent user', async () => {
        const loginDto = {
          username: 'nonexistent',
          password: 'password123',
        };

        await request(app.getHttpServer())
          .post('/auth/login')
          .send(loginDto)
          .expect(401);
      });

      it('should fail with missing fields', async () => {
        await request(app.getHttpServer())
          .post('/auth/login')
          .send({ username: testUsername })
          .expect(400);
      });
    });

    describe('/auth/refresh (POST)', () => {
      let refreshToken: string;

      beforeEach(async () => {
        // Register a user and get refresh token
        const registerResponse = await request(app.getHttpServer())
          .post('/auth/register')
          .send({
            username: testUsername,
            password: 'password123',
          });

        refreshToken = registerResponse.body.refresh_token;
      });

      it('should refresh tokens with valid refresh token', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken })
          .expect(201);

        expect(response.body).toHaveProperty('access_token');
        expect(response.body).toHaveProperty('refresh_token');
        expect(typeof response.body.access_token).toBe('string');
        expect(typeof response.body.refresh_token).toBe('string');

        // Verify new tokens are different from the old ones
        expect(response.body.refresh_token).not.toBe(refreshToken);
      });

      it('should fail with invalid refresh token', async () => {
        await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken: 'invalid-token' })
          .expect(401);
      });

      it('should fail with missing refresh token', async () => {
        await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({})
          .expect(400);
      });

      it('should fail with refresh token after logout', async () => {
        // First get auth token
        const loginResponse = await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            username: testUsername,
            password: 'password123',
          });

        const accessToken = loginResponse.body.access_token;

        // Logout
        await request(app.getHttpServer())
          .post('/auth/logout')
          .set('Authorization', `Bearer ${accessToken}`)
          .expect(201);

        // Try to use the old refresh token
        await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken })
          .expect(401);
      });

      it('should allow using new refresh token after refresh', async () => {
        // First refresh
        const firstRefreshResponse = await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken })
          .expect(201);

        const newRefreshToken = firstRefreshResponse.body.refresh_token;

        // Verify the new token is different from the old one
        expect(newRefreshToken).not.toBe(refreshToken);

        // New refresh token should work
        const secondRefreshResponse = await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken: newRefreshToken })
          .expect(201);

        expect(secondRefreshResponse.body).toHaveProperty('access_token');
        expect(secondRefreshResponse.body).toHaveProperty('refresh_token');

        // Verify tokens keep rotating
        expect(secondRefreshResponse.body.refresh_token).not.toBe(
          newRefreshToken,
        );
      });
    });

    describe('/auth/logout (POST)', () => {
      let refreshToken: string;

      beforeEach(async () => {
        // Register a user and get tokens
        const registerResponse = await request(app.getHttpServer())
          .post('/auth/register')
          .send({
            username: testUsername,
            password: 'password123',
          });

        authToken = registerResponse.body.access_token;
        refreshToken = registerResponse.body.refresh_token;
      });

      it('should logout successfully with valid access token', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/logout')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(201);

        expect(response.body).toHaveProperty(
          'message',
          'Logged out successfully',
        );
      });

      it('should fail without authentication', async () => {
        await request(app.getHttpServer()).post('/auth/logout').expect(401);
      });

      it('should fail with invalid token', async () => {
        await request(app.getHttpServer())
          .post('/auth/logout')
          .set('Authorization', 'Bearer invalid-token')
          .expect(401);
      });

      it('should invalidate refresh token after logout', async () => {
        // Logout
        await request(app.getHttpServer())
          .post('/auth/logout')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(201);

        // Verify refresh token no longer works
        await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken })
          .expect(401);
      });
    });
  });

  describe('Posts Endpoints', () => {
    let postId: string;

    beforeEach(async () => {
      // Create a user and get auth token
      const registerResponse = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          username: testUsername,
          password: 'password123',
        });

      authToken = registerResponse.body.access_token;
    });

    describe('/posts (GET)', () => {
      it('should get all posts without authentication', async () => {
        const response = await request(app.getHttpServer())
          .get('/posts')
          .expect(200);

        expect(Array.isArray(response.body)).toBe(true);
      });

      it('should return posts with author information', async () => {
        // Create a post first
        await request(app.getHttpServer())
          .post('/posts')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ content: 'Test post content' });

        const response = await request(app.getHttpServer())
          .get('/posts')
          .expect(200);

        expect(response.body.length).toBe(1);
        expect(response.body[0]).toHaveProperty('content', 'Test post content');
        expect(response.body[0]).toHaveProperty('author');
        expect(response.body[0].author).toHaveProperty(
          'username',
          testUsername,
        );
      });
    });

    describe('/posts (POST)', () => {
      it('should create a post with valid authentication', async () => {
        const createPostDto = {
          content: 'This is a test post',
        };

        const response = await request(app.getHttpServer())
          .post('/posts')
          .set('Authorization', `Bearer ${authToken}`)
          .send(createPostDto)
          .expect(201);

        expect(response.body).toHaveProperty('content', 'This is a test post');
        expect(response.body).toHaveProperty('author');
        expect(response.body.author).toHaveProperty('username', testUsername);
        expect(response.body).toHaveProperty('id');

        postId = response.body.id;
      });

      it('should fail without authentication', async () => {
        const createPostDto = {
          content: 'This is a test post',
        };

        await request(app.getHttpServer())
          .post('/posts')
          .send(createPostDto)
          .expect(401);
      });

      it('should fail with invalid token', async () => {
        const createPostDto = {
          content: 'This is a test post',
        };

        await request(app.getHttpServer())
          .post('/posts')
          .set('Authorization', 'Bearer invalid-token')
          .send(createPostDto)
          .expect(401);
      });

      it('should fail with invalid data', async () => {
        await request(app.getHttpServer())
          .post('/posts')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ content: '' }) // empty content
          .expect(400);
      });
    });

    describe('/posts/:id (GET)', () => {
      beforeEach(async () => {
        // Create a post
        const response = await request(app.getHttpServer())
          .post('/posts')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ content: 'Test post for retrieval' });

        postId = response.body.id;
      });

      it('should get a specific post without authentication', async () => {
        const response = await request(app.getHttpServer())
          .get(`/posts/${postId}`)
          .expect(200);

        expect(response.body).toHaveProperty(
          'content',
          'Test post for retrieval',
        );
        expect(response.body).toHaveProperty('author');
        expect(response.body.author).toHaveProperty('username', testUsername);
      });

      it('should return 404 for non-existent post', async () => {
        await request(app.getHttpServer())
          .get('/posts/non-existent-id')
          .expect(404);
      });
    });

    describe('/posts/:id (PUT)', () => {
      beforeEach(async () => {
        // Create a post
        const response = await request(app.getHttpServer())
          .post('/posts')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ content: 'Original content' });

        postId = response.body.id;
      });

      it('should update own post with valid authentication', async () => {
        const updatePostDto = {
          content: 'Updated content',
        };

        const response = await request(app.getHttpServer())
          .put(`/posts/${postId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .send(updatePostDto)
          .expect(200);

        expect(response.body).toHaveProperty('content', 'Updated content');
        expect(response.body).toHaveProperty('author');
        expect(response.body.author).toHaveProperty('username', testUsername);
      });

      it('should fail without authentication', async () => {
        await request(app.getHttpServer())
          .put(`/posts/${postId}`)
          .send({ content: 'Updated content' })
          .expect(401);
      });

      it("should fail when updating another user's post", async () => {
        // Create another user
        const anotherUser = `anotheruser_${Date.now()}`;
        const anotherUserResponse = await request(app.getHttpServer())
          .post('/auth/register')
          .send({
            username: anotherUser,
            password: 'password123',
          });

        const anotherUserToken = anotherUserResponse.body.access_token;

        await request(app.getHttpServer())
          .put(`/posts/${postId}`)
          .set('Authorization', `Bearer ${anotherUserToken}`)
          .send({ content: "Trying to update another user's post" })
          .expect(403);
      });
    });

    describe('/posts/:id (DELETE)', () => {
      beforeEach(async () => {
        // Create a post
        const response = await request(app.getHttpServer())
          .post('/posts')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ content: 'Post to be deleted' });

        postId = response.body.id;
      });

      it('should delete own post with valid authentication', async () => {
        await request(app.getHttpServer())
          .delete(`/posts/${postId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        // Verify post is deleted
        await request(app.getHttpServer()).get(`/posts/${postId}`).expect(404);
      });

      it('should fail without authentication', async () => {
        await request(app.getHttpServer())
          .delete(`/posts/${postId}`)
          .expect(401);
      });

      it("should fail when deleting another user's post", async () => {
        // Create another user
        const anotherUser = `anotheruser_${Date.now()}`;
        const anotherUserResponse = await request(app.getHttpServer())
          .post('/auth/register')
          .send({
            username: anotherUser,
            password: 'password123',
          });

        const anotherUserToken = anotherUserResponse.body.access_token;

        await request(app.getHttpServer())
          .delete(`/posts/${postId}`)
          .set('Authorization', `Bearer ${anotherUserToken}`)
          .expect(403);
      });
    });
  });
});
