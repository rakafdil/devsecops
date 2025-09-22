FROM php:8.1-apache

# Install required extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN apt-get update && apt-get install -y \
    libzip-dev \
    zip \
    && docker-php-ext-install zip

# Install Redis extension
RUN pecl install redis && docker-php-ext-enable redis

# Enable Apache modules
RUN a2enmod rewrite
RUN a2enmod headers

# Set working directory
WORKDIR /var/www/html

# Copy source code
COPY src/ /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html
RUN chmod -R 755 /var/www/html

# Enable sessions
RUN echo "session.save_handler = files" >> /usr/local/etc/php/conf.d/session.ini
RUN echo "session.save_path = /tmp" >> /usr/local/etc/php/conf.d/session.ini
RUN echo "session.cookie_secure = 0" >> /usr/local/etc/php/conf.d/session.ini
RUN echo "session.cookie_httponly = 0" >> /usr/local/etc/php/conf.d/session.ini

EXPOSE 80
