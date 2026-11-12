<?php
// ============================================================
//  index.php — Login Page
//  VARS · Visiting Airmen Record System
// ============================================================
require_once __DIR__ . '/security.php';   // handles session_start + headers

// Already logged in → go straight to dashboard
if (!empty($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

require_once __DIR__ . '/db.php';

$pdo       = getPDO();
$locations = getLocations($pdo, true);

$error = '';
if (($_GET['reason'] ?? '') === 'timeout') {
    $error = 'Your session expired due to inactivity. Please sign in again.';
} elseif (($_GET['reason'] ?? '') === 'disabled') {
    $error = 'Your account access has been disabled by the administrator.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();   // 403 + exit on bad token

    $username = post_str('username', 60);
    $password = trim($_POST['password'] ?? '');   // don't strip password chars
    $location = strtoupper(post_str('location', 60));

    $validLocCodes = array_column($locations, 'code');

    if ($username === '' || $password === '' || $location === '') {
        $error = 'Please enter username, password, and select a location.';

    } elseif (!in_array($location, $validLocCodes, true)) {
        $error = 'Selected camp location is invalid or inactive.';

    } elseif (login_is_locked($username)) {
        $mins  = ceil(login_lockout_remaining($username) / 60);
        $error = "Too many failed attempts. Please wait {$mins} minute(s) before trying again.";

    } else {
        $stmt = $pdo->prepare('SELECT id, password, svs_no, `rank`, name, role, location, is_active FROM users WHERE username = ? LIMIT 1');
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            if (!(int)$user['is_active']) {
                $error = 'Your account access has been disabled by the administrator.';
            } elseif (strtoupper($user['location']) !== $location) {
                login_record_failure($username);
                $error = 'Access denied for the selected location. Please select your assigned camp.';
            } else {
                login_clear_failures($username);
                session_regenerate_id(true);
                $displayName = trim(($user['rank'] ? $user['rank'] . ' ' : '') . ($user['name'] ?: $username));
                $_SESSION['user_id']   = $user['id'];
                $_SESSION['full_name'] = $displayName;
                $_SESSION['username']  = $username;
                $_SESSION['role']      = $user['role'];
                $_SESSION['location']  = strtoupper($user['location']);
                header('Location: dashboard.php');
                exit;
            }
        } else {
            login_record_failure($username);
            // Generic message — do not reveal whether username exists
            $error = 'Invalid username or password. Please try again.';
            if (login_is_locked($username)) {
                $mins  = ceil(LOGIN_LOCKOUT_SECONDS / 60);
                $error = "Account locked after too many failures. Try again in {$mins} minutes.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VARS · Login</title>

  <!-- Tailwind CSS CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              50:  '#eff6ff',
              100: '#dbeafe',
              400: '#60a5fa',
              500: '#3b82f6',
              600: '#2563eb',
              700: '#1d4ed8',
              800: '#1e40af',
              900: '#1e3a8a',
            }
          }
        }
      }
    }
  </script>

  <!-- Alpine.js CDN -->
  <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>

  <style>
    [x-cloak] { display: none !important; }

    /* Animated gradient background */
    .animated-bg {
      background: linear-gradient(135deg, #020c1b 0%, #0a1628 25%, #0d2137 55%, #0f2d4a 80%, #0a1e35 100%);
      background-size: 400% 400%;
      animation: gradientShift 12s ease infinite;
    }
    @keyframes gradientShift {
      0%   { background-position: 0%   50%; }
      50%  { background-position: 100% 50%; }
      100% { background-position: 0%   50%; }
    }

    /* White login card */
    .login-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      box-shadow: 0 20px 50px rgba(2, 12, 27, 0.45);
    }

    /* Input focus ring */
    .input-field {
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      transition: border-color .2s, box-shadow .2s, background-color .2s;
    }
    .input-field:focus {
      background: #ffffff;
      border-color: #2563eb;
      box-shadow: 0 0 0 3px rgba(37,99,235,0.18);
      outline: none;
    }

    /* Floating particles */
    .particles {
      position: absolute;
      inset: 0;
      overflow: hidden;
      pointer-events: none;
    }
    .particle {
      position: absolute;
      border-radius: 50%;
      opacity: .15;
      animation: float linear infinite;
    }
    @keyframes float {
      0%   { transform: translateY(100vh) rotate(0deg); opacity: 0; }
      10%  { opacity: .15; }
      90%  { opacity: .15; }
      100% { transform: translateY(-10vh) rotate(720deg); opacity: 0; }
    }
  </style>
</head>

<body class="h-full animated-bg relative flex items-center justify-center min-h-screen"
      x-data="{ showPass: false }">

  <!-- Floating particles -->
  <div class="particles" aria-hidden="true">
    <?php
    $sizes = [24,16,32,12,20,28,10,18];
    $colors = ['bg-blue-500','bg-blue-400','bg-cyan-400','bg-sky-400'];
    foreach (range(1,12) as $i) :
      $size  = $sizes[array_rand($sizes)];
      $color = $colors[array_rand($colors)];
      $left  = rand(2, 95);
      $delay = rand(0, 15);
      $dur   = rand(14, 28);
    ?>
    <div class="particle <?= $color ?>"
         style="width:<?= $size ?>px;height:<?= $size ?>px;
                left:<?= $left ?>%;
                animation-delay:<?= $delay ?>s;
                animation-duration:<?= $dur ?>s;">
    </div>
    <?php endforeach; ?>
  </div>

  <!-- Login Card -->
  <div class="login-card rounded-2xl w-full max-w-[360px] mx-4 p-6 relative z-10">

    <!-- Logo / Header -->
    <div class="text-center mb-5">
      <div class="inline-flex items-center justify-center w-12 h-12 rounded-full
                  bg-gradient-to-br from-blue-600 to-blue-800 shadow-md shadow-blue-600/30 mb-2.5">
        <!-- Shield icon -->
        <svg class="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12 1L3 5v6c0 5.25 3.75 10.15 9 11.25C17.25 21.15 21 16.25 21 11V5l-9-4z"/>
        </svg>
      </div>
      <h1 class="text-2xl font-black text-slate-900 tracking-tight">VARS</h1>
      <p class="text-blue-700 text-[11px] mt-0.5 font-bold tracking-widest uppercase">
        Visiting Airmen Record System
      </p>
      <div class="mt-2.5 h-px bg-gradient-to-r from-transparent via-slate-300 to-transparent"></div>
    </div>

    <!-- Error Alert -->
    <?php if ($error !== ''): ?>
    <div class="flex items-start gap-2.5 bg-red-50 border border-red-200
                text-red-700 rounded-xl px-3.5 py-2.5 mb-4 text-xs font-medium" role="alert">
      <svg class="w-4 h-4 mt-0.5 flex-shrink-0 text-red-600" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0
          1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
      </svg>
      <?= htmlspecialchars($error) ?>
    </div>
    <?php endif; ?>

    <!-- Login Form -->
    <form method="POST" action="" class="space-y-3.5" novalidate>
      <?php csrf_field(); ?>

      <!-- Username -->
      <div>
        <label for="username" class="block text-xs font-bold text-slate-800 mb-1">
          Username
        </label>
        <div class="relative">
          <span class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor"
                 stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
            </svg>
          </span>
          <input id="username" name="username" type="text" autocomplete="username"
                 required placeholder="Enter username"
                 value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                 class="input-field w-full pl-9 pr-3 py-2.5 rounded-xl text-slate-900
                        placeholder-slate-400 text-sm font-medium" />
        </div>
      </div>

      <!-- Password -->
      <div>
        <label for="password" class="block text-xs font-bold text-slate-800 mb-1">
          Password
        </label>
        <div class="relative">
          <span class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor"
                 stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0
                       002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
          </span>
          <input id="password" name="password"
                 :type="showPass ? 'text' : 'password'"
                 autocomplete="current-password"
                 required placeholder="Enter password"
                 class="input-field w-full pl-9 pr-10 py-2.5 rounded-xl text-slate-900
                        placeholder-slate-400 text-sm font-medium" />
          <button type="button" @click="showPass = !showPass"
                  class="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500
                         hover:text-blue-600 transition-colors">
            <svg x-show="!showPass" class="w-4 h-4" fill="none" stroke="currentColor"
                 stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943
                       9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
            </svg>
            <svg x-show="showPass" x-cloak class="w-4 h-4" fill="none" stroke="currentColor"
                 stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97
                       9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242
                       4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0
                       0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0
                       01-4.132 5.411m0 0L21 21"/>
            </svg>
          </button>
        </div>
      </div>

      <!-- Location -->
      <div>
        <label for="location" class="block text-xs font-bold text-slate-800 mb-1">
          Location
        </label>
        <div class="relative">
          <span class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor"
                 stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/>
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"/>
            </svg>
          </span>
          <?php $selectedLoc = strtoupper($_POST['location'] ?? 'SJP'); ?>
          <select id="location" name="location" required
                  class="input-field w-full pl-9 pr-9 py-2.5 rounded-xl text-slate-900 text-sm font-medium appearance-none cursor-pointer">
            <option value="" class="bg-white text-slate-500">— Select Location —</option>
            <?php foreach ($locations as $loc):
              $code  = $loc['code'];
              $label = $loc['name'] ? "{$code} — {$loc['name']}" : $code;
            ?>
            <option value="<?= htmlspecialchars($code) ?>"
                    class="bg-white text-slate-900"
                    <?= $selectedLoc === $code ? 'selected' : '' ?>>
              <?= htmlspecialchars($label) ?>
            </option>
            <?php endforeach; ?>
          </select>
          <span class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
            <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/>
            </svg>
          </span>
        </div>
      </div>

      <!-- Submit -->
      <button type="submit"
              class="w-full py-2.5 px-5 rounded-xl font-bold text-white text-sm
                     bg-gradient-to-r from-blue-600 to-blue-800
                     hover:from-blue-700 hover:to-blue-900
                     active:scale-[.98] transition-all duration-200
                     shadow-md shadow-blue-700/30 mt-1">
        Sign In to VARS
      </button>
    </form>

    <!-- Footer note -->
    <p class="text-center text-slate-500 text-[11px] font-medium mt-5">
      Police Advanced Course 2026/02 &nbsp;·&nbsp; <span class="text-amber-600 font-semibold">Under Testing Mode</span>
    </p>
  </div>

</body>
</html>

