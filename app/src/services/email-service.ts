import nodemailer from 'nodemailer';
import { config } from '../lib/config';

export class EmailService {
  private static transporter: nodemailer.Transporter;

  static {
    try {
      // Initialize MailHog transporter
      this.transporter = nodemailer.createTransport({
        host: 'localhost',
        port: 1025,
        secure: false,
        auth: undefined,
        tls: {
          rejectUnauthorized: false
        }
      });
      console.log("📧 EmailService initialized successfully with MailHog");
    } catch (error) {
      console.error("❌ Failed to initialize EmailService:", error);
      throw error;
    }
  }

  // Send password reset email using MailHog
  static async sendPasswordResetEmail(email: string, resetToken: string): Promise<void> {
    const resetUrl = `http://localhost:3000/reset-password?token=${resetToken}`;
    
    const emailData = {
      from: 'noreply@medicalapp.com',
      to: email,
      subject: 'Resetare Parolă - Medical App',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333; text-align: center;">Resetare Parolă</h2>
          <p style="color: #666;">Salut,</p>
          <p style="color: #666;">Ai solicitat resetarea parolei pentru contul tău Medical App.</p>
          <p style="color: #666;">Click pe link-ul de mai jos pentru a reseta parola:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" 
               style="background-color: #007bff; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius:5px; display: inline-block;">
              Resetează Parola
            </a>
          </div>
          
          <p style="color: #666;">Sau copiază și lipește acest link în browser:</p>
          <p style="color: #007bff; word-break: break-all;">${resetUrl}</p>
          
          <p style="color: #666; font-size: 14px;">Link-ul va expira în 1 oră.</p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
          
          <p style="color: #999; font-size: 12px; text-align: center;">
            Dacă nu ai solicitat resetarea parolei, ignoră acest email.
          </p>
        </div>
      `
    };

    try {
      const result = await this.transporter.sendMail(emailData);
      console.log("📧 Email sent successfully to MailHog:", email);
      console.log("📧 Email message ID:", result.messageId);
      console.log("📧 Preview at: http://localhost:8025");
    } catch (error) {
      console.error('❌ Failed to send password reset email:', error);
      throw error;
    }
  }

  // Send password reset confirmation email
  static async sendPasswordResetConfirmationEmail(email: string): Promise<void> {
    const emailData = {
      from: 'noreply@medicalapp.com',
      to: email,
      subject: 'Parola Resetată cu Succes - Medical App',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333; text-align: center;">Parola Resetată cu Succes</h2>
          <p style="color: #666;">Salut,</p>
          <p style="color: #666;">Parola contului tău Medical App a fost resetată cu succes.</p>
          
          <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <p style="color: #333; margin: 0;">Dacă nu ai fost tu care a resetat parola, te rugăm să contactezi imediat suportul.</p>
          </div>
          
          <p style="color: #666;">Poți acum să te autentifici cu noua parolă.</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="http://localhost:3000/login" 
               style="background-color: #28a745; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius:5px; display: inline-block;">
              Autentificare
            </a>
          </div>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
          
          <p style="color: #999; font-size: 12px; text-align: center;">
            Acesta este un email automat, te rugăm să nu răspunzi.
          </p>
        </div>
      `
    };

    try {
      const result = await this.transporter.sendMail(emailData);
      console.log("📧 Confirmation email sent successfully to MailHog:", email);
      console.log("📧 Email message ID:", result.messageId);
      console.log("📧 Preview at: http://localhost:8025");
    } catch (error) {
      console.error('❌ Failed to send password reset confirmation email:', error);
      throw error;
    }
  }
}
