<?php
require_once 'config.php';
require_once 'auth.php';
require_once 'security.php';

// Initialize secure session and check authentication
securePage();

// Check if user is admin
if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
    header("Location: login.php");
    exit();
}

// Get admin information
$admin_id = $_SESSION['user_id'];
$sql = "SELECT name, email, last_login FROM users WHERE id = ? AND role = 'admin'";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $admin_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$admin = mysqli_fetch_assoc($result);

// Get user statistics
$stats = [
    'total_users' => 0,
    'active_users' => 0,
    'pending_users' => 0,
    'suspended_users' => 0
];

$sql = "SELECT status, COUNT(*) as count FROM users GROUP BY status";
$result = mysqli_query($conn, $sql);
while ($row = mysqli_fetch_assoc($result)) {
    $stats['total_users'] += $row['count'];
    switch ($row['status']) {
        case 'active':
            $stats['active_users'] = $row['count'];
            break;
        case 'pending':
            $stats['pending_users'] = $row['count'];
            break;
        case 'suspended':
            $stats['suspended_users'] = $row['count'];
            break;
    }
}

// Get recent user registrations
$sql = "SELECT id, name, email, status, created_at FROM users ORDER BY created_at DESC LIMIT 5";
$recent_users = mysqli_query($conn, $sql);

// Get recent login attempts
$sql = "SELECT u.email, la.attempt_time, la.success, la.ip_address 
        FROM login_attempts la 
        JOIN users u ON la.email = u.email 
        ORDER BY la.attempt_time DESC LIMIT 5";
$recent_logins = mysqli_query($conn, $sql);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Addwise</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Poppins', sans-serif;
        }

        body {
            background: #f5f7fb;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            color: #333;
            font-size: 1.8em;
        }

        .admin-info {
            text-align: right;
        }

        .admin-info p {
            color: #666;
            margin: 5px 0;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
        }

        .stat-card .number {
            color: #333;
            font-size: 2em;
            font-weight: 600;
        }

        .stat-card.active { border-top: 4px solid #4CAF50; }
        .stat-card.pending { border-top: 4px solid #FFC107; }
        .stat-card.suspended { border-top: 4px solid #F44336; }
        .stat-card.total { border-top: 4px solid #2196F3; }

        .section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .section h2 {
            color: #333;
            font-size: 1.4em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #f0f0f0;
        }

        th {
            color: #666;
            font-weight: 500;
        }

        td {
            color: #333;
        }

        .status-badge {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.8em;
        }

        .status-active { background: #E8F5E9; color: #2E7D32; }
        .status-pending { background: #FFF3E0; color: #E65100; }
        .status-suspended { background: #FFEBEE; color: #C62828; }

        .action-btn {
            padding: 8px 15px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.3s ease;
        }

        .action-btn.view { background: #E3F2FD; color: #1565C0; }
        .action-btn.edit { background: #E8F5E9; color: #2E7D32; }
        .action-btn.suspend { background: #FFEBEE; color: #C62828; }

        .action-btn:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }

        .logout-btn {
            background: #FFEBEE;
            color: #C62828;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
        }

        .logout-btn:hover {
            background: #FFCDD2;
            transform: translateY(-1px);
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .header {
                flex-direction: column;
                text-align: center;
            }

            .admin-info {
                text-align: center;
                margin-top: 10px;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            table {
                display: block;
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Admin Dashboard</h1>
            </div>
            <div class="admin-info">
                <p>Welcome, <?php echo htmlspecialchars($admin['name']); ?></p>
                <p>Last login: <?php echo date('M d, Y H:i', strtotime($admin['last_login'])); ?></p>
                <a href="logout.php" class="logout-btn">Logout</a>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card total">
                <h3>Total Users</h3>
                <div class="number"><?php echo $stats['total_users']; ?></div>
            </div>
            <div class="stat-card active">
                <h3>Active Users</h3>
                <div class="number"><?php echo $stats['active_users']; ?></div>
            </div>
            <div class="stat-card pending">
                <h3>Pending Users</h3>
                <div class="number"><?php echo $stats['pending_users']; ?></div>
            </div>
            <div class="stat-card suspended">
                <h3>Suspended Users</h3>
                <div class="number"><?php echo $stats['suspended_users']; ?></div>
            </div>
        </div>

        <div class="section">
            <h2>Recent User Registrations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Status</th>
                        <th>Registered</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($user = mysqli_fetch_assoc($recent_users)): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($user['name']); ?></td>
                        <td><?php echo htmlspecialchars($user['email']); ?></td>
                        <td>
                            <span class="status-badge status-<?php echo $user['status']; ?>">
                                <?php echo ucfirst($user['status']); ?>
                            </span>
                        </td>
                        <td><?php echo date('M d, Y', strtotime($user['created_at'])); ?></td>
                        <td>
                            <button class="action-btn view">View</button>
                            <button class="action-btn edit">Edit</button>
                            <?php if ($user['status'] !== 'suspended'): ?>
                            <button class="action-btn suspend">Suspend</button>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Recent Login Attempts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Time</th>
                        <th>Status</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($login = mysqli_fetch_assoc($recent_logins)): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($login['email']); ?></td>
                        <td><?php echo date('M d, Y H:i', strtotime($login['attempt_time'])); ?></td>
                        <td>
                            <span class="status-badge <?php echo $login['success'] ? 'status-active' : 'status-suspended'; ?>">
                                <?php echo $login['success'] ? 'Success' : 'Failed'; ?>
                            </span>
                        </td>
                        <td><?php echo htmlspecialchars($login['ip_address']); ?></td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Add click handlers for action buttons
        document.querySelectorAll('.action-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const action = this.classList.contains('view') ? 'view' :
                             this.classList.contains('edit') ? 'edit' : 'suspend';
                const row = this.closest('tr');
                const email = row.cells[1].textContent;
                
                // Handle different actions
                switch(action) {
                    case 'view':
                        // Implement view user details
                        alert('View user: ' + email);
                        break;
                    case 'edit':
                        // Implement edit user
                        alert('Edit user: ' + email);
                        break;
                    case 'suspend':
                        if (confirm('Are you sure you want to suspend this user?')) {
                            // Implement suspend user
                            alert('Suspend user: ' + email);
                        }
                        break;
                }
            });
        });
    </script>
</body>
</html> 