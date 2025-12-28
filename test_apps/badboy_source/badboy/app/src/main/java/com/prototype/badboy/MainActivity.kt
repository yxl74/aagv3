package com.prototype.badboy

import android.Manifest
import android.app.DownloadManager
import android.content.Context
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.ContactsContract
import android.provider.Settings
import android.telephony.SmsManager
import android.widget.Toast
import dalvik.system.DexClassLoader
import java.io.File
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.IntentFilter
import android.provider.CallLog
import androidx.core.content.FileProvider
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.prototype.badboy.ui.theme.BadboyTheme

class MainActivity : ComponentActivity() {
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        // Handle permission results if needed
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            BadboyTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Greeting(
                        name = "Android",
                        modifier = Modifier.padding(innerPadding),
                        requestPermissions = { perms ->
                            requestPermissionLauncher.launch(perms)
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun Greeting(
    name: String,
    modifier: Modifier = Modifier,
    requestPermissions: (Array<String>) -> Unit = {}
) {
    val context = LocalContext.current
    var androidId by remember { mutableStateOf("") }
    var displayText by remember { mutableStateOf("") }

    Column(
        modifier = modifier.fillMaxSize()
    ) {
        // App header with version
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(androidx.compose.ui.graphics.Color(0xFF1a1a1a))
                .padding(vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "SAFE TEST APP",
                style = androidx.compose.ui.text.TextStyle(
                    color = androidx.compose.ui.graphics.Color.Green,
                    fontSize = androidx.compose.ui.unit.TextUnit(12f, androidx.compose.ui.unit.TextUnitType.Sp),
                    fontWeight = androidx.compose.ui.text.font.FontWeight.Bold
                ),
                modifier = Modifier
                    .background(androidx.compose.ui.graphics.Color(0xFF004D00))
                    .padding(horizontal = 12.dp, vertical = 4.dp)
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "BADBOY",
                style = androidx.compose.ui.text.TextStyle(
                    color = androidx.compose.ui.graphics.Color.Red,
                    fontSize = androidx.compose.ui.unit.TextUnit(32f, androidx.compose.ui.unit.TextUnitType.Sp),
                    fontWeight = androidx.compose.ui.text.font.FontWeight.Bold
                )
            )
            Text(
                text = "animalistic tendencies",
                style = androidx.compose.ui.text.TextStyle(
                    color = androidx.compose.ui.graphics.Color.Gray,
                    fontSize = androidx.compose.ui.unit.TextUnit(14f, androidx.compose.ui.unit.TextUnitType.Sp),
                    fontStyle = androidx.compose.ui.text.font.FontStyle.Italic
                ),
                modifier = Modifier.padding(top = 2.dp)
            )
            Text(
                text = "v1.0.0",
                style = androidx.compose.ui.text.TextStyle(
                    color = androidx.compose.ui.graphics.Color.White,
                    fontSize = androidx.compose.ui.unit.TextUnit(18f, androidx.compose.ui.unit.TextUnitType.Sp),
                    fontWeight = androidx.compose.ui.text.font.FontWeight.Medium
                ),
                modifier = Modifier.padding(top = 4.dp)
            )
        }
        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Top
        ) {
            Button(
                onClick = {
                    androidId = Settings.Secure.getString(
                        context.contentResolver,
                        Settings.Secure.ANDROID_ID
                    )
                    displayText = "Android ID: $androidId"
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Android ID")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_SMS)
                        == PackageManager.PERMISSION_GRANTED) {
                        val cursor: Cursor? = context.contentResolver.query(
                            Uri.parse("content://sms/inbox"),
                            arrayOf("_id", "address", "body", "date"),
                            null,
                            null,
                            "date DESC"
                        )
                        val count = cursor?.count ?: 0
                        cursor?.close()
                        displayText = "SMS Count: $count"
                    } else {
                        requestPermissions(arrayOf(Manifest.permission.READ_SMS))
                        displayText = "Requesting SMS permission..."
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Read SMS")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CONTACTS)
                        == PackageManager.PERMISSION_GRANTED) {
                        val cursor: Cursor? = context.contentResolver.query(
                            ContactsContract.Contacts.CONTENT_URI,
                            null,
                            null,
                            null,
                            null
                        )
                        val count = cursor?.count ?: 0
                        cursor?.close()
                        displayText = "Contacts Count: $count"
                    } else {
                        requestPermissions(arrayOf(Manifest.permission.READ_CONTACTS))
                        displayText = "Requesting Contacts permission..."
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Get Contacts")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    if (ContextCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS)
                        == PackageManager.PERMISSION_GRANTED) {
                        try {
                            val smsManager = SmsManager.getDefault()
                            displayText = "SMS API called (not actually sending)"
                        } catch (e: Exception) {
                            displayText = "SMS API error: ${e.message}"
                        }
                    } else {
                        requestPermissions(arrayOf(Manifest.permission.SEND_SMS))
                        displayText = "Requesting SMS permission..."
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Send SMS")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CALENDAR)
                        == PackageManager.PERMISSION_GRANTED) {
                        val cursor: Cursor? = context.contentResolver.query(
                            Uri.parse("content://com.android.calendar/events"),
                            arrayOf("_id", "title", "dtstart"),
                            null,
                            null,
                            null
                        )
                        val count = cursor?.count ?: 0
                        cursor?.close()
                        displayText = "Calendar Events Count: $count"
                    } else {
                        requestPermissions(arrayOf(Manifest.permission.READ_CALENDAR))
                        displayText = "Requesting Calendar permission..."
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Read Calendar")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    try {
                        // Check if we can install unknown apps
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                            if (!context.packageManager.canRequestPackageInstalls()) {
                                val intent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
                                    .setData(Uri.parse("package:${context.packageName}"))
                                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                                context.startActivity(intent)
                                displayText = "Dropper: Enable unknown sources first"
                                return@Button
                            }
                        }

                        // Download F-Droid APK (open source app store)
                        val downloadManager = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
                        val apkUrl = "https://f-droid.org/F-Droid.apk"
                        val request = DownloadManager.Request(Uri.parse(apkUrl))
                            .setTitle("F-Droid")
                            .setDescription("Downloading APK...")
                            .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "fdroid.apk")
                            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                            .setAllowedOverMetered(true)
                            .setAllowedOverRoaming(true)
                        val downloadId = downloadManager.enqueue(request)
                        displayText = "Dropper: Downloading F-Droid (ID: $downloadId)"
                    } catch (e: Exception) {
                        displayText = "Dropper error: ${e.message}"
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Dropper (Download)")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    try {
                        val apkFile = File(
                            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                            "fdroid.apk"
                        )
                        if (!apkFile.exists()) {
                            displayText = "Install: APK not found. Download first."
                            return@Button
                        }

                        val apkUri = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                            FileProvider.getUriForFile(
                                context,
                                "${context.packageName}.fileprovider",
                                apkFile
                            )
                        } else {
                            Uri.fromFile(apkFile)
                        }

                        val intent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(apkUri, "application/vnd.android.package-archive")
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
                        }
                        context.startActivity(intent)
                        displayText = "Install: Launching installer..."
                    } catch (e: Exception) {
                        displayText = "Install error: ${e.message}"
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Install APK")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    try {
                        val dexPath = File(context.filesDir, "classes.dex").absolutePath
                        val optimizedDir = context.getDir("dex", Context.MODE_PRIVATE).absolutePath
                        val classLoader = DexClassLoader(
                            dexPath,
                            optimizedDir,
                            null,
                            context.classLoader
                        )
                        displayText = "DexClassLoader: Initialized (path: $dexPath)"
                    } catch (e: Exception) {
                        displayText = "DexClassLoader error: ${e.message}"
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("DexClassLoader")
            }

            Spacer(modifier = Modifier.height(8.dp))

            // OVERLAY ABUSE - SYSTEM_ALERT_WINDOW
            Button(
                onClick = {
                    try {
                        val canDraw = Settings.canDrawOverlays(context)
                        if (!canDraw) {
                            val intent = Intent(
                                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                Uri.parse("package:${context.packageName}")
                            )
                            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            context.startActivity(intent)
                            displayText = "Overlay: Grant permission first!"
                        } else {
                            // Show an overlay window
                            val wm = context.getSystemService(Context.WINDOW_SERVICE) as android.view.WindowManager
                            val params = android.view.WindowManager.LayoutParams(
                                android.view.WindowManager.LayoutParams.MATCH_PARENT,
                                200,
                                android.view.WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                                android.view.WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                                android.graphics.PixelFormat.TRANSLUCENT
                            )
                            params.gravity = android.view.Gravity.TOP
                            val overlay = android.widget.TextView(context).apply {
                                text = "OVERLAY ABUSE DEMO - Tap anywhere"
                                setBackgroundColor(android.graphics.Color.parseColor("#CC000000"))
                                setTextColor(android.graphics.Color.RED)
                                textSize = 18f
                                gravity = android.view.Gravity.CENTER
                                setPadding(20, 40, 20, 40)
                                setOnClickListener { wm.removeView(this) }
                            }
                            wm.addView(overlay, params)
                            displayText = "Overlay: Showing overlay! Tap it to dismiss."
                        }
                    } catch (e: Exception) {
                        displayText = "Overlay error: ${e.message}"
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                    containerColor = androidx.compose.ui.graphics.Color(0xFFFF5722)
                )
            ) {
                Text("Overlay Abuse")
            }

            Spacer(modifier = Modifier.height(8.dp))

            // ACCESSIBILITY ABUSE - open settings + show what we can do
            Button(
                onClick = {
                    try {
                        // Check if our service is enabled
                        val enabledServices = Settings.Secure.getString(
                            context.contentResolver,
                            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
                        ) ?: ""
                        val isEnabled = enabledServices.contains(context.packageName)

                        if (!isEnabled) {
                            val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            context.startActivity(intent)
                            displayText = "Accessibility: Enable BadAccessibilityService!\n" +
                                "Capabilities: Keylogging, UI automation, credential theft"
                        } else {
                            displayText = "Accessibility: ENABLED!\n" +
                                "Now capturing: keystrokes, screen content, gestures\n" +
                                "Can: click buttons, fill forms, bypass prompts"
                        }
                    } catch (e: Exception) {
                        displayText = "Accessibility error: ${e.message}"
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                    containerColor = androidx.compose.ui.graphics.Color(0xFFE91E63)
                )
            ) {
                Text("Accessibility Abuse")
            }

            Spacer(modifier = Modifier.height(8.dp))

            // EXECUTION - Runtime.exec
            Button(
                onClick = {
                    try {
                        val process = Runtime.getRuntime().exec("id")
                        val output = process.inputStream.bufferedReader().readText()
                        process.waitFor()
                        displayText = "Exec: $output"
                    } catch (e: Exception) {
                        displayText = "Exec error: ${e.message}"
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Execution")
            }

            Spacer(modifier = Modifier.height(8.dp))

            // SRCALLS - Read Call Log
            Button(
                onClick = {
                    if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CALL_LOG)
                        == PackageManager.PERMISSION_GRANTED) {
                        val cursor: Cursor? = context.contentResolver.query(
                            CallLog.Calls.CONTENT_URI,
                            arrayOf(CallLog.Calls._ID, CallLog.Calls.NUMBER),
                            null,
                            null,
                            null
                        )
                        val count = cursor?.count ?: 0
                        cursor?.close()
                        displayText = "Call Log Count: $count"
                    } else {
                        requestPermissions(arrayOf(Manifest.permission.READ_CALL_LOG))
                        displayText = "Requesting Call Log permission..."
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Read Call Log")
            }

            Spacer(modifier = Modifier.height(8.dp))

            // BOOT - simulate checking boot receiver
            Button(
                onClick = {
                    displayText = "Boot: RECEIVE_BOOT_COMPLETED declared in manifest"
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Boot Receiver")
            }

            Spacer(modifier = Modifier.height(8.dp))

            // DEVICEADMIN - open device admin settings
            Button(
                onClick = {
                    try {
                        val intent = Intent().apply {
                            setClassName(
                                "com.android.settings",
                                "com.android.settings.DeviceAdminSettings"
                            )
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        }
                        context.startActivity(intent)
                        displayText = "DeviceAdmin: Settings opened"
                    } catch (e: Exception) {
                        displayText = "DeviceAdmin error: ${e.message}"
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Device Admin")
            }
        }

        if (displayText.isNotEmpty()) {
            Text(
                text = displayText,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    BadboyTheme {
        Greeting("Android")
    }
}