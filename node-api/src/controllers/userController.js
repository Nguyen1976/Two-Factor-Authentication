// Author: TrungQuanDev | https://youtube.com/@trungquandev
import { StatusCodes } from 'http-status-codes'
import { pickUser } from '~/utils/formatters'
import { authenticator } from 'otplib'
import QRCode from 'qrcode'

// LƯU Ý: Trong ví dụ về xác thực 2 lớp Two-Factor Authentication (2FA) này thì chúng ta sẽ sử dụng nedb-promises để lưu và truy cập dữ liệu từ một file JSON. Coi như file JSON này là Database của dự án.
const Datastore = require('nedb-promises')
const UserDB = Datastore.create('src/database/users.json')
const TwoFactorSecretKeyDB = Datastore.create(
  'src/database/2fa_secret_keys.json'
)
const UserSessionDB = Datastore.create(
  'src/database/user_sessions.json'
)

const SERVICE_NAME = '2FA' //Tên này sẽ hiện thị ra khi dùng app để quét qr thường là tên của dự án

const login = async (req, res) => {
  try {
    const user = await UserDB.findOne({ email: req.body.email })
    // Không tồn tại user
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }
    // Kiểm tra mật khẩu "đơn giản". LƯU Ý: Thực tế phải dùng bcryptjs để hash mật khẩu, đảm bảo mật khẩu được bảo mật. Ở đây chúng ta làm nhanh gọn theo kiểu so sánh string để tập trung vào nội dung chính là 2FA.
    // Muốn học về bcryptjs cũng như toàn diện kiến thức đầy đủ về việc làm một trang web Nâng Cao thì các bạn có thể theo dõi khóa MERN Stack Advanced này. (Public lên phần hội viên của kênh vào tháng 12/2024)
    // https://www.youtube.com/playlist?list=PLP6tw4Zpj-RJbPQfTZ0eCAXH_mHQiuf2G
    if (user.password !== req.body.password) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Wrong password!' })
      return
    }

    res.status(StatusCodes.OK).json(pickUser(user))
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const getUser = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    res.status(StatusCodes.OK).json(pickUser(user))
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const logout = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Xóa phiên của user trong Database > user_sessions tại đây khi đăng xuất

    res.status(StatusCodes.OK).json({ loggedOut: true })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const get2FA_QRCode = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    let twoFactorSecretKeyKeyValue = null

    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({
      user_id: user._id
    })
    if (!twoFactorSecretKey) {
      //Nếu chưa có secretKey của user thì tạo mới
      let newTwoFactorSecretKey = await TwoFactorSecretKeyDB.insert({
        user_id: user._id,
        value: authenticator.generateSecret() //Đây là mã secret key nó sẽ là random nhưng phải random theo một cái chuẩn của otplib
      })
      twoFactorSecretKeyKeyValue = newTwoFactorSecretKey.value
    } else {
      //Ngược lại user có rồi lấy ra sử dụng luôn
      twoFactorSecretKeyKeyValue = twoFactorSecretKey.value
    }
    const otpAuthToken = await authenticator.keyuri(
      user.username,
      SERVICE_NAME,
      twoFactorSecretKeyKeyValue
    )
    const QRCodeImageUrl = await QRCode.toDataURL(otpAuthToken)
    res.status(StatusCodes.OK).json({ qrcode: QRCodeImageUrl })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const setup2FA = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    //Lấy secretKey của user từ bảng 2fa secret
    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({
      user_id: user._id
    })
    if(!twoFactorSecretKey) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'Two-Factor Secret Key not found!' })
      return
    }

    //Nếu user có secret key thì sẽ kiểm tra otp token từ client gửi lên
    const clientOtpToken = req.body.otpToken
    
    //verify tokentừ otp ở client quét được và value trong bảng 2fe secret key
    const isValid = await authenticator.verify({
      token: clientOtpToken,
      secret: twoFactorSecretKey.value
    })

    


    if(!isValid) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Invalid OTP Token' })
      return
    }
    //Sau khi xác thực 2FA thành công
    const updateduser = await UserDB.update(
      { _id: user._id },
      { $set: { require_2fa: true } },
      { returnUpdatedDocs: true }//return kết quả đã update thành công
    )

    UserDB.compactDatafileAsync()

    //Lúc này tùy vào sepec dự án sẽ dữ phiên đăng nhập hợp lệ cho user, hoặc yêu cầu bắt buộc user phải đăng nhập lại. Tùy nhu cầu
    //Ở đây là vấn giữ phiên đăng nhập hợp lệ cho user giống như google họ làm
    //hoặc user đang đăng nhập trên 1 device khác thì mới yêu cầu 2fe

    //Vì user lúc này mới bật 2fa lên chúng ta tạo một phiên đăng nhập  mới dựa vào triunfh duyệt hiện tại
    const newUserSession = await UserSessionDB.insert({
      user_id: user._id,
      device_id: req.headers['user-agent'], //Lấy user-agent từ req header để định danh trình duyệt của user
      is_2fa_verified: true, //Xác thực là 1 phiên hợp lệ
      last_login: new Date().valueOf()
    })

    res.status(StatusCodes.OK).json({
      ...pickUser(updateduser),
      is_2fa_verified: newUserSession.is_2fa_verified,
      last_login: newUserSession.last_login
    })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

export const userController = {
  login,
  getUser,
  logout,
  get2FA_QRCode,
  setup2FA
}
