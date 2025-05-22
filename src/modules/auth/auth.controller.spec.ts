import { faker } from '@faker-js/faker';
import { INestApplication } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { SEQUELIZE } from '../../core/constants';
import { SignupDto } from '../dto/signup.dto';
import { AuthModule } from './auth.module';

describe('AuthController', () => {
  const validPassword = 'SomePassword123!';
  const accessToken = 'access-token';
  const defaultUser: SignupDto = {
    name: faker.person.fullName(),
    email: faker.internet.email(),
    password: validPassword,
  };
  let app: INestApplication;
  let mockModule: TestingModule;

  beforeAll(async () => {
    mockModule = await Test.createTestingModule({
      imports: [AuthModule],
    })
      .overrideProvider(JwtService)
      .useValue({
        signAsync: () => accessToken,
      })
      .compile();

    // create the app instance
    app = mockModule.createNestApplication();
    await app.init();

    // signup default user
    await request(app.getHttpServer())
      .post('/auth/signup')
      .send(defaultUser)
      .expect(201)
      .expect((response) => {
        expect(response.body.accessToken).toBe(accessToken);
      });
  });

  afterAll(async () => {
    await app.close();
    await mockModule.get(SEQUELIZE).close();
  });

  describe('POST /auth/login', () => {
    it('should login a user successfully', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: defaultUser.email, password: defaultUser.password })
        .expect(200);

      expect(response.body.accessToken).toBe(accessToken);
    });

    describe('should return bad request error 400 if', () => {
      it('email is missing', async () => {
        await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            password: defaultUser.password,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('email cannot be empty');
          });
      });

      it('email is empty', async () => {
        await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            email: '',
            password: defaultUser.password,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('email cannot be empty');
          });
      });

      it('password is missing', async () => {
        await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            email: defaultUser.email,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('password cannot be empty');
          });
      });

      it('password is empty', async () => {
        await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            email: defaultUser.email,
            password: '',
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('password cannot be empty');
          });
      });

      describe('should return unauthorized error 401 if', () => {
        it('email is invalid', async () => {
          const nonExistentUserEmail = 'non-user@test.go.ke';

          await request(app.getHttpServer())
            .post('/auth/login')
            .send({
              email: nonExistentUserEmail,
              password: defaultUser.password,
            })
            .expect(401)
            .expect((response) => {
              expect(response.body.message).toBe('Invalid email or password');
            });
        });

        it('password is invalid', async () => {
          const invalidPassword = 'invalid-password';

          await request(app.getHttpServer())
            .post('/auth/login')
            .send({
              email: defaultUser.email,
              password: invalidPassword,
            })
            .expect(401)
            .expect((response) => {
              expect(response.body.message).toBe('Invalid email or password');
            });
        });
      });
    });
  });

  describe('POST /auth/signup', () => {
    it('should signup a user successfully', async () => {
      const newUser: SignupDto = {
        name: faker.person.fullName(),
        email: faker.internet.email(),
        password: validPassword,
      };

      await request(app.getHttpServer())
        .post('/auth/signup')
        .send(newUser)
        .expect(201)
        .expect((response) => {
          expect(response.body.accessToken).toBe(accessToken);
        });
    });

    describe('should return bad request error 400 if', () => {
      it('name is missing', async () => {
        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            email: defaultUser.email,
            password: defaultUser.password,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('name cannot be empty');
          });
      });

      it('name is empty', async () => {
        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: '',
            email: defaultUser.email,
            password: defaultUser.password,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('name cannot be empty');
          });
      });

      it('email is missing', async () => {
        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            password: defaultUser.password,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('email cannot be empty');
          });
      });

      it('email is empty', async () => {
        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            email: '',
            password: defaultUser.password,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('email cannot be empty');
          });
      });

      it('email is invalid', async () => {
        const invalidEmail = 'invalid-email';
        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            email: invalidEmail,
            password: defaultUser.password,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('invalid email address');
          });
      });

      it('password is missing', async () => {
        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            email: defaultUser.email,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('password cannot be empty');
          });
      });

      it('password is empty', async () => {
        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            email: defaultUser.email,
            password: '',
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe('password cannot be empty');
          });
      });

      it('password is less than 10 characters', async () => {
        const invalidPassword = 'short';

        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            email: defaultUser.email,
            password: invalidPassword,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe(
              'password must be at least 10 characters',
            );
          });
      });

      it('password does not contain an uppercase letter', async () => {
        const invalidPassword = 'lowercasepassword';

        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            email: defaultUser.email,
            password: invalidPassword,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe(
              'password must contain at least one uppercase letter',
            );
          });
      });

      it('password does not contain a digit', async () => {
        const invalidPassword = 'PasswordWithoutDigit';

        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            email: defaultUser.email,
            password: invalidPassword,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe(
              'password must contain at least one digit',
            );
          });
      });

      it('password does not contain a special character', async () => {
        const invalidPassword = 'PasswordWithoutSpecialCharacter123';

        await request(app.getHttpServer())
          .post('/auth/signup')
          .send({
            name: defaultUser.name,
            email: defaultUser.email,
            password: invalidPassword,
          })
          .expect(400)
          .expect((response) => {
            expect(response.body.message).toBe(
              'password must contain at least one special character',
            );
          });
      });
    });

    it('should return conflict error 409 if user already exists', async () => {
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send(defaultUser)
        .expect(409)
        .expect((response) => {
          expect(response.body.message).toBe(
            'User with email already exists',
          );
        });
    });

    it('should return conflict error 409 if user with email already exists', async () => {
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send(defaultUser)
        .expect(409)
        .expect((response) => {
          expect(response.body.message).toBe(
            'User with email already exists',
          );
        });
    });
  });
});
