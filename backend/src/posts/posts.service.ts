import { Injectable, ForbiddenException } from '@nestjs/common';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { PrismaService } from '../prisma.service';

@Injectable()
export class PostsService {
  constructor(private prisma: PrismaService) {}

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
}
