'use strict';

const app = require('../server');
const chai = require('chai');
const chaiHttp = require('chai-http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const { JWT_SECRET, TEST_MONGODB_URI } = require('../config');

const User = require('../models/user');

const seedUser = require('../db/seed/users');


const expect = chai.expect;

chai.use(chaiHttp);


describe('Auth endpoints', function () {

  before(function () {
    return mongoose.connect(TEST_MONGODB_URI)
      .then(() => mongoose.connection.db.dropDatabase());
  });

  beforeEach(function () {
    const testUser = seedUser[0];
    return User.hashPassword(testUser.password)
      .then(digest => {
        return User.create({
          _id: testUser._id,
          fullname: testUser.fullname,
          username: testUser.username,
          password: digest
        });
      });
  });

  afterEach(function () {
    return mongoose.connection.db.dropDatabase();
  });

  after(function () {
    return mongoose.disconnect();
  });

  describe('/api/login', function () {
    it('Should return a valid auth token', function () {
      return chai.request(app)
        .post('/api/login')
        .send({ username: 'user0', password: '$2a$10$QJCIX42iD5QMxLRgHHBJre2rH6c6nI24UysmSYtkmeFv6X8uS1kgi' })
        .then(res => {
          expect(res).to.have.status(200);
          expect(res.body).to.be.an('object'); 
          expect(res.body.authToken).to.be.a('string');

          const payload = jwt.verify(res.body.authToken, JWT_SECRET);
          expect(payload.user).to.not.have.property('password');
          expect(payload.user).to.deep.equal({ 
            'id': '333333333333333333333300',
            'username':'user0', 
            'fullname':'User Zero' 
          });
        });
    });  
    it('Should reject requests with incorrect username', function () {
      return chai.request(app)
        .post('/api/login')
        .send({ username:'incorrectusername', password:'$2a$10$QJCIX42iD5QMxLRgHHBJre2rH6c6nI24UysmSYtkmeFv6X8uS1kgi' })
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });
    });

    it('Should reject requests with incorrect password', function () {
      return chai.request(app)
        .post('/api/login')
        .send({ username: 'user0', password:'wrongpassword' })
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });
    });

    it('Should reject request with no credentials', function (){
      return chai.request(app)
        .post('/api/login')
        //.send({ username: '', password: '' })
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(400);
        });
    });
  });
});
