
// const sender = { name: "Secure Auth", email: env.MAILTRAP_SENDER_EMAIL };

export const sendMail = async (
  to,
  subject,
  text,
  html
) => {
  try {
    mailtrapClient.send({
      from: sender,
      to: [{ email: to }],
      subject,
      html,
      text,
    });
  } catch (error) {
    throw new ApiError(500, `Failed to send "${subject}" email`);
  }
};