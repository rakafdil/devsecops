    </main>

    <footer class="footer">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h5>🎯 VulnWeb - Vulnerable Web Application</h5>
                    <p class="text-muted">
                        This application is intentionally vulnerable for educational purposes.<br>
                        <strong>⚠️ DO NOT use in production environments!</strong>
                    </p>
                </div>
                <div class="col-md-6">
                    <h6>Vulnerability Categories</h6>
                    <ul class="list-unstyled">
                        <li><span class="vulnerability-badge">SQLi</span> SQL Injection</li>
                        <li><span class="vulnerability-badge">XSS</span> Cross-Site Scripting</li>
                        <li><span class="vulnerability-badge">AUTH</span> Broken Authentication</li>
                        <li><span class="vulnerability-badge">BAC</span> Broken Access Control</li>
                        <li><span class="vulnerability-badge">PRIV</span> Privilege Escalation</li>
                    </ul>
                </div>
            </div>
            <hr>
            <div class="row">
                <div class="col-12 text-center">
                    <p class="text-muted mb-0">
                        Created for Cyber Kill Chain Training | 
                        <a href="?debug=1" class="text-decoration-none">Debug Mode</a> |
                        <a href="vulnerabilities.php" class="text-decoration-none">Vulnerability Guide</a>
                    </p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- VULNERABLE: Inline JavaScript without CSP -->
    <script>
        // VULNERABLE: Client-side validation that can be bypassed
        function validateForm(form) {
            return true; // Always return true - no real validation
        }
        
        // VULNERABLE: Exposing sensitive information in client-side
        var debugMode = <?php echo isset($_GET['debug']) ? 'true' : 'false'; ?>;
        if (debugMode) {
            console.log('Debug mode enabled');
            console.log('Current user:', <?php echo json_encode(getCurrentUser()); ?>);
        }
    </script>
</body>
</html>