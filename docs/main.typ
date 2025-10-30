#set enum(numbering: "a)")

= Dokumentasi Tugas PBKK E07 - Authentication

#v(0.3cm)

Nama: Juang Maulana Taruna Putra
NRP: 5025231257

#v(0.5cm)

== 1. Backend - Auth Service (auth.service.ts)

=== a. Constructor & Helpers

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  private generateTokens(username: string) {
    // TODO: Implement token generation
    const payload = { sub: username, username };

    const accessToken = this.jwtService.sign(payload);

    // Add a small nonce to refresh token payload so it rotates on each generation
    const refreshPayload = { ...payload, nonce: `${Date.now()}_${Math.random()}` };
    const refreshToken = this.jwtService.sign(refreshPayload, {
      secret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key-change-in-production',
      expiresIn: '7d', // Refresh token expires in 7 days
    });

    return { accessToken, refreshToken };
  }

  private async updateRefreshToken(username: string, refreshToken: string) {
    // TODO: Implement refresh token update
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    
    await this.prisma.user.update({
      where: { username },
      data: { refreshToken: hashedRefreshToken },
    });
  }
Service ini menginjeksikan PrismaService untuk interaksi database dan JwtService untuk membuat token. Fungsi generateTokens membuat access token (payload standar, 15 menit) dan refresh token (payload + nonce unik, 7 hari). Fungsi updateRefreshToken melakukan hashing pada refresh token baru menggunakan bcrypt dan menyimpannya di database user.

#line(length: 100%)

=== b. Register

  async register(registerDto: RegisterDto) {
    // TODO: Implement user registration
    const { username, password } = registerDto;

    // Check if user already exists
    const existingUser = await this.prisma.user.findUnique({
      where: { username },
    });

    if (existingUser) {
      throw new ConflictException('Username already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await this.prisma.user.create({
      data: {
        username,
        password: hashedPassword,
      },
    });

    // Generate tokens
    const tokens = this.generateTokens(user.username);

    // Update refresh token
    await this.updateRefreshToken(user.username, tokens.refreshToken);

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      user: { username: user.username },
    };
  }
Fungsi register menerima RegisterDto (username, password). Pertama, ia memeriksa apakah username sudah ada; jika ya, ConflictException (409) dilempar. Password di-hash menggunakan bcrypt sebelum disimpan ke database. Setelah user dibuat, fungsi ini memanggil generateTokens dan updateRefreshToken untuk membuat sesi baru, lalu mengembalikan token dan data user.

#line(length: 100%)

=== c. Login

  async login(loginDto: LoginDto) {
    // TODO: Implement user login
    const { username, password } = loginDto;

    // Find user
    const user = await this.prisma.user.findUnique({
      where: { username },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const tokens = this.generateTokens(user.username);

    // Update refresh token
    await this.updateRefreshToken(user.username, tokens.refreshToken);

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      user: { username: user.username },
    };
  }
Fungsi login menerima LoginDto. Ia mencari user berdasarkan username; jika tidak ada, UnauthorizedException (401) dilempar. Selanjutnya, ia membandingkan password yang diberikan dengan hash di database menggunakan bcrypt.compare. Jika tidak cocok, UnauthorizedException dilempar. Jika kredensial valid, token baru dibuat dan refresh token di-update, lalu dikembalikan ke client.

#line(length: 100%)

=== d. Refresh Token

  async refreshToken(refreshTokenDto: RefreshTokenDto) {
     // TODO: Implement token refresh
    const { refreshToken } = refreshTokenDto;

    try {
      // Verify refresh token
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key-change-in-production',
      });

      // Find user
      const user = await this.prisma.user.findUnique({
        where: { username: payload.username },
      });

      if (!user || !user.refreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Verify stored refresh token
      const refreshTokenMatch = await bcrypt.compare(refreshToken, user.refreshToken);

      if (!refreshTokenMatch) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Generate new tokens
      const tokens = this.generateTokens(user.username);

      // Update refresh token
      await this.updateRefreshToken(user.username, tokens.refreshToken);

      return {
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
Fungsi refreshToken menerima RefreshTokenDto. Ia memverifikasi JWT menggunakan secret refresh token. Ia mencari user dari payload token dan memeriksa apakah user atau refresh token-nya masih ada (jika user logout, token akan null). Ia kemudian membandingkan token yang diterima dengan hash di database. Jika semua valid, token baru (access dan refresh) dibuat, disimpan, dan dikembalikan (token rotation).

#line(length: 100%)

=== e. Logout

  async logout(username: string) {
    // TODO: Implement user logout
    // Clear refresh token
    await this.prisma.user.update({
      where: { username },
      data: { refreshToken: null },
    });

    return { message: 'Logged out successfully' };
  }
Fungsi logout menerima username dari payload JWT. Implementasi logout ini menginvalidsi sesi refresh dengan mengatur field refreshToken user di database menjadi null. Ini mencegah refresh token lama digunakan untuk mendapatkan access token baru.

#line(length: 100%)

== 2. Backend - Posts Service (posts.service.ts)

=== a. Create

  create(data: CreatePostDto, authorId: string) {
    // TODO: Implement post creation
    // - Create a new post with data and authorId
    // - Include author (username only), replyTo, and replies in the response
    // - For replyTo: include id, content, and author's username
    // - For replies: include id, content, createdAt, and author's username, ordered by createdAt asc
    return this.prisma.post.create({
      data: {
        content: data.content,
        authorId,
        replyToId: data.replyToId,
      },
      include: {
        author: {
          select: {
            username: true,
          },
        },
        replyTo: {
          select: {
            id: true,
            content: true,
            author: {
              select: {
                username: true,
              },
            },
          },
        },
        replies: {
          select: {
            id: true,
            content: true,
            createdAt: true,
            author: {
              select: {
                username: true,
              },
            },
          },
          orderBy: {
            createdAt: 'asc',
          },
        },
      },
    });
    throw new Error('Not implemented');
  }
Fungsi create menerima CreatePostDto (content, replyToId opsional) dan authorId (dari JWT). Ia membuat post baru di database. Opsi include digunakan untuk mengembalikan data post yang baru dibuat beserta relasi: author (hanya username), replyTo (post yang dibalas, termasuk author-nya), dan replies (termasuk author-nya, diurutkan ascending).

#line(length: 100%)

=== b. Find All

  findAll() {
    // TODO: Implement finding all posts
    // - Fetch all posts from the database
    // - Include author (username only), replyTo, and replies in the response
    // - For replyTo: include id, content, and author's username
    // - For replies: include id, content, createdAt, and author's username, ordered by createdAt asc
    return this.prisma.post.findMany({
      include: {
        author: {
          select: {
            username: true,
          },
        },
        replyTo: {
          select: {
            id: true,
            content: true,
            author: {
              select: {
                username: true,
              },
            },
          },
        },
        replies: {
          select: {
            id: true,
            content: true,
            createdAt: true,
            author: {
              select: {
                username: true,
              },
            },
          },
          orderBy: {
            createdAt: 'asc',
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
    throw new Error('Not implemented');
  }
Fungsi findAll mengambil semua post (findMany). Ia menyertakan relasi author, replyTo, dan replies dengan struktur yang sama seperti pada fungsi create. Post utama diurutkan berdasarkan createdAt descending (terbaru dulu).

#line(length: 100%)

=== c. Find One

  findOne(id: string) {
    // TODO: Implement finding a single post
    // - Find a post by its id
    // - Include author (username only), replyTo, and replies in the response
    // - For replyTo: include id, content, and author's username
    // - For replies: include id, content, createdAt, and author's username, ordered by createdAt asc
    return this.prisma.post.findUnique({
      where: { id },
      include: {
        author: {
          select: {
            username: true,
          },
        },
        replyTo: {
          select: {
            id: true,
            content: true,
            author: {
              select: {
                username: true,
              },
            },
          },
        },
        replies: {
          select: {
            id: true,
            content: true,
            createdAt: true,
            author: {
              select: {
                username: true,
              },
            },
          },
          orderBy: {
            createdAt: 'asc',
          },
        },
      },
    });
    throw new Error('Not implemented');
  }
Fungsi findOne mengambil satu post unik berdasarkan id. Sama seperti findAll, ia menyertakan relasi author, replyTo, dan replies.

#line(length: 100%)

=== d. Update

  async update(id: string, data: UpdatePostDto, userId: string) {
    // TODO: Implement post update
    // Find the post by id
    const post = await this.prisma.post.findUnique({
      where: { id },
    });

    // Throw ForbiddenException if post not found
    if (!post) {
      throw new ForbiddenException('Post not found');
    }

    // Verify the post belongs to the user (authorId === userId)
    if (post.authorId !== userId) {
      throw new ForbiddenException('You can only update your own posts');
    }

    // Update the post with the new data
    return this.prisma.post.update({
      where: { id },
      data: {
        content: data.content,
      },
      include: {
        // ... (include options same as findOne)
      },
    });
    throw new Error('Not implemented');
  }
Fungsi update menerima id post, UpdatePostDto, dan userId (dari JWT). Ia mencari post terlebih dahulu. Jika tidak ditemukan, ForbiddenException (403) dilempar. Ia lalu memverifikasi bahwa authorId post sama dengan userId yang melakukan request. Jika tidak, ForbiddenException dilempar. Jika user adalah pemilik, post di-update dan data baru dikembalikan beserta relasi.

#line(length: 100%)

=== e. Remove

  async remove(id: string, userId: string) {
    // TODO: Implement post deletion
    // Find the post by id
    const post = await this.prisma.post.findUnique({
      where: { id },
    });

    // Throw ForbiddenException if post not found
    if (!post) {
      throw new ForbiddenException('Post not found');
    }

    // Verify the post belongs to the user (authorId === userId)
    if (post.authorId !== userId) {
      throw new ForbiddenException('You can only delete your own posts');
    }

    // Delete the post from the database
    await this.prisma.post.delete({
      where: { id },
    });

    return { message: 'Post deleted successfully' };
  }
Fungsi remove memiliki logika otorisasi yang sama dengan update. Ia memeriksa keberadaan post dan kepemilikan. Jika user adalah pemilik, post akan dihapus (prisma.post.delete). Berdasarkan skema Prisma (onDelete: Cascade), ini juga akan menghapus semua replies dari post tersebut secara rekursif.

#line(length: 100%)

== 3. Backend - Auth Module (auth.module.ts)

@Module({
  imports: [
    // TODO
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      signOptions: { expiresIn: '15m' }, // Access token expires in 15 minutes
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, PrismaService],
  exports: [AuthService],
})
export class AuthModule {}
Module ini bertanggung jawab untuk otentikasi. Ia mengimpor PassportModule untuk integrasi strategy dan JwtModule untuk manajemen JWT. JwtModule.register mengkonfigurasi access token, menggunakan JWT_SECRET dari environment variable dan mengatur masa berlaku 15 menit. Ia mendaftarkan AuthController serta menyediakan AuthService, JwtStrategy, dan PrismaService untuk digunakan di dalam module ini.

#line(length: 100%)

== 4. Backend - JWT Strategy (jwt.strategy.ts)

=== a. Constructor

  constructor(private prisma: PrismaService) {
    super({
      // TODO
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
    });
  }
Strategy ini digunakan oleh JwtAuthGuard untuk memvalidasi access token. Constructor memanggil super untuk mengkonfigurasi PassportStrategy. jwtFromRequest diatur untuk mengekstrak token dari Authorization: Bearer <token> header. ignoreExpiration diatur ke false agar token yang kadaluarsa ditolak. secretOrKey menggunakan secret yang sama dengan yang didefinisikan di AuthModule.

#line(length: 100%)

=== b. Validate

  async validate(payload: any) {
    // TODO
    const jwtPayload = plainToClass(JwtPayloadDto, payload);
    const errors = await validate(jwtPayload);
    
    if (errors.length > 0) {
      throw new UnauthorizedException('Invalid token payload');
    }

    const user = await this.prisma.user.findUnique({
      where: { username: jwtPayload.username },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return { username: user.username };
  }
Metode validate dipanggil oleh Passport setelah token berhasil diverifikasi dan payload-nya di-decode. Payload tersebut divalidasi terhadap JwtPayloadDto (memastikan sub dan username ada). Ia kemudian memeriksa apakah user yang ada di payload masih ada di database. Jika user valid, fungsi ini mengembalikan objek { username: user.username }, yang kemudian akan diinjeksikan oleh Passport ke request.user di controller.

#line(length: 100%)

== 5. Perbandingan Metode Autentikasi (Session vs. JWT)

Pada metode berbasis sesi, server membuat ID sesi unik saat pengguna melakukan login, menyimpan ID tersebut dalam database, dan mengirimkannya ke klien melalui cookie. Setiap permintaan dari klien kemudian diverifikasi dengan mencari ID sesi tersebut di database server. Sedangkan pada autentikasi berbasis JWT, server menghasilkan token JSON yang ditandatangani secara kriptografis menggunakan secret key dan memuat data pengguna (payload), kemudian token tersebut dikirim ke klien. Pada setiap permintaan, klien mengirimkan token ini melalui header Authorization, dan server cukup memverifikasi tanda tangan token tanpa perlu menyimpannya di database.

Dalam konteks arsitektur project ini, yang memisahkan antara API backend (NestJS) dan aplikasi frontend (Next.js), metode JWT lebih diunggulkan. Hal ini karena JWT bersifat stateless, sehingga server tidak perlu melakukan pencarian data di database pada setiap permintaan, melainkan hanya fokus pada verifikasi tanda tangan token. Sifat ini juga memudahkan skalabilitas horizontal, karena beberapa instance server dapat memvalidasi token selama menggunakan secret key yang sama tanpa memerlukan sticky session atau penyimpanan sesi terpusat. Selain itu, token mudah untuk disimpan di localStorage pada frontend dan dilampirkan pada header permintaan.

Meskipun ada kelemahan dalam JWT terkait sulitnya proses invalidasi token sebelum masa expired berakhir, project ini mengatasi hal tersebut dengan menggunakan access token berumur pendek (15 menit) dan mekanisme refresh token yang tersimpan di database. Saat pengguna melakukan logout, refresh token dapat dihapus sehingga akses dapat dihentikan secara efektif. Dengan demikian, meskipun autentikasi berbasis sesi lebih sederhana untuk aplikasi monolitik, autentikasi berbasis JWT dinilai lebih fleksibel dan skalabel untuk kebutuhan API modern.

Jadi, menurut saya Authentication berbasis JWT lebih bagus dari Authentication berbasis Session.