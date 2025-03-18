// Author: TrungQuanDev | https://youtube.com/@trungquandev
import express from 'express'
import { userController } from '~/controllers/userController'

const Router = express.Router()

Router.route('/login')
  .post(userController.login)

Router.route('/:id/logout')
  .delete(userController.logout)

Router.route('/:id')
  .get(userController.getUser)

Router.route('/:id/get_2fa_qr_code') //Để lấy qr code cho xác thực 2 lớp
  .get(userController.get2FA_QRCode)


export const userRoute = Router
