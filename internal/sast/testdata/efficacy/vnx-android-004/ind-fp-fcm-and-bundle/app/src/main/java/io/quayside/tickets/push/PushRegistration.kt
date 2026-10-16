package io.quayside.tickets.push

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.core.content.edit
import com.google.firebase.messaging.FirebaseMessagingService

class TicketsMessagingService : FirebaseMessagingService() {

    override fun onNewToken(token: String) {
        getSharedPreferences("push", Context.MODE_PRIVATE).edit {
            putString("fcm_token", token)
        }
    }
}

fun resetPasswordArgs(email: String, resetToken: String): Bundle {
    val args = Bundle()
    args.putString("email", email)
    args.putString("reset_token", resetToken)
    return args
}

fun openResetScreen(context: Context, resetToken: String) {
    val intent = Intent(context, ResetPasswordActivity::class.java)
    intent.putExtra("reset_token", resetToken)
    context.startActivity(intent)
}
