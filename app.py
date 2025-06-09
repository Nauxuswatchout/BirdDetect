from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_from_directory, session, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import boto3
import hmac
import base64
import hashlib
import os
import random
import string
import re
import requests
from botocore.exceptions import ClientError
from werkzeug.utils import secure_filename
from sqlalchemy.orm import Session
from datetime import datetime
import time
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
import json
from urllib.parse import urlparse, quote

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key'  # 在生产环境中应该使用环境变量
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 限制上传文件大小为16MB
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# AWS Cognito配置
AWS_REGION = 'us-east-1'
USER_POOL_ID = 'us-east-1_g4SvG2N1E'
CLIENT_ID = '4quucr17sofk8c874jlhm29g0o'
CLIENT_SECRET = 'bim9cvkkua3443kam6vrr5jar1umu8p0rmdi6b8c520r9knm42r'
API_BASE_URL = "https://8wpmntawc1.execute-api.us-east-1.amazonaws.com/dev"

# User model and helper functions
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def setup_aws_credentials():
    """Setup AWS credentials and return a Cognito client"""
    credentials = {
        'AWS_ACCESS_KEY_ID': 'ASIAU4XJBVESD6765W5H',
        'AWS_SECRET_ACCESS_KEY': 'enZ03Eoa55kovX7Nf8w7qAD3TY7pdIoOBux5EJVi',
        'AWS_SESSION_TOKEN': 'IQoJb3JpZ2luX2VjEDcaCXVzLXdlc3QtMiJHMEUCICPdK7vrnkBgEde1zRVmoN+NBqnaP3JDWPP+cB6KOS4JAiEA0HcKKd+sVnegyjOomxHve7ZKD+P3epy6t3z/NlLHtgwqtQIIEBABGgwzMzY1Njk5MzYxNjQiDBP2H5pKPCQxlQlJ/iqSAvFZnrOQGJ9gTlU1cpiABM6Gs3CobAGmZDNQ/Bgq9AglgVDfSVcCE64xIBp4wqmUA16hk2zVXmfOUZJ/2eVxGok086J6+MCNOLfueihcpjV2fWHy8Uu+645u7hUfAGuqJqX0/9dqJzNc7C3uC+22G9CAuEsxTs0n3GC/D0iSCgw5rrv7qP1d/3bwNLPHSp42BahafvWRQ4b7evJrBEsU4GnsckPYp68aqoovfIWlSFrMY8YjMPp4XrgZgdWc6+dsbCRMIu/wN/NuGGAgwTY4mA+jvoTguGz0WgyjXBZXNsNjmR0Hn3bV1PmQ5AdU0Q4sbQr6wiYa+xtA0Lahutp+MdCYfH/nT/HvSYkPrIA7hSIGsYIw9K76wQY6nQFxrKYX0F3kZjUJq/RrxBUXM7kngM5z8aB4+1iD0h4zrrAAyOv3r45c92LerDbvJtrg8p2S0prZ9eS3klnDc496es0ApWz/CZFXdf7b5YrHEWaeaxt4FcpAzrfgDqiXaUByGDg5W7/jX5Yr63VvuRQSbFvFSKsmd3NQGmctWu5a3IP2HNb4KRbYokjiuMteq1mZ88xFU1wX75JxqMWW',
        'AWS_DEFAULT_REGION': AWS_REGION
    }
    
    for key, value in credentials.items():
        os.environ[key] = value
    
    try:
        return boto3.client('cognito-idp', region_name=AWS_REGION)
    except Exception as e:
        app.logger.error(f'Failed to create Cognito client: {str(e)}')
        raise

def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'),
                   msg=str(msg).encode('utf-8'),
                   digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

def generate_random_password():
    lowercase = ''.join(random.choices(string.ascii_lowercase, k=3))
    uppercase = ''.join(random.choices(string.ascii_uppercase, k=3))
    digits = ''.join(random.choices(string.digits, k=2))
    special = ''.join(random.choices('!@#$%^&*', k=2))
    password = lowercase + uppercase + digits + special
    password_list = list(password)
    random.shuffle(password_list)
    return ''.join(password_list)

def get_aws_auth_headers(method, url, body=None):
    """Generate AWS SigV4 signed headers"""
    credentials = Credentials(
        access_key=os.environ['AWS_ACCESS_KEY_ID'],
        secret_key=os.environ['AWS_SECRET_ACCESS_KEY'],
        token=os.environ['AWS_SESSION_TOKEN']
    )

    request = AWSRequest(
        method=method,
        url=url,
        data=json.dumps(body) if body else None,
        headers={
            'Content-Type': 'application/json',
            'Host': '8wpmntawc1.execute-api.us-east-1.amazonaws.com'
        }
    )

    SigV4Auth(credentials, "execute-api", AWS_REGION).add_auth(request)
    return dict(request.headers)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search')
@login_required
def search():
    if not session.get('id_token'):
        flash('请先登录')
        return redirect(url_for('login'))
    return render_template('search.html')

@app.route('/upload')
@login_required
def upload():
    if not session.get('id_token'):
        flash('Please login to upload images')
        return redirect(url_for('login'))
    return render_template('upload.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            # fallback for HTML form submission
            username = request.form.get('username')
            password = request.form.get('password')

        setup_aws_credentials()
        client = boto3.client('cognito-idp', region_name=AWS_REGION)

        try:
            auth_response = client.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': get_secret_hash(username)
                }
            )

            # Create or update local user
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username, password='[COGNITO_MANAGED]')
                db.session.add(user)
                db.session.commit()

            login_user(user)

            session['access_token'] = auth_response['AuthenticationResult']['AccessToken']
            session['id_token'] = auth_response['AuthenticationResult']['IdToken']
            session['refresh_token'] = auth_response['AuthenticationResult']['RefreshToken']

            return jsonify({
                'status': 'success',
                'message': 'Login successful',
                'tokens': {
                    'access_token': auth_response['AuthenticationResult']['AccessToken'],
                    'id_token': auth_response['AuthenticationResult']['IdToken'],
                    'refresh_token': auth_response['AuthenticationResult']['RefreshToken']
                }
            })

        except ClientError as e:
            error_message = str(e)
            app.logger.error(f'Login error for user {username}: {error_message}')

            if 'NotAuthorizedException' in error_message:
                message = "Invalid username or password"
            elif 'UserNotConfirmedException' in error_message:
                message = "Email not verified"
            else:
                message = "Login failed, please try again later"
            return jsonify({'status': 'error', 'message': message}), 400

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({
                    'status': 'error',
                    'message': 'No JSON data received'
                }), 400

            username = str(data.get('username', '')).strip()
            email = str(data.get('email', '')).strip()
            first_name = str(data.get('firstName', '')).strip()
            last_name = str(data.get('lastName', '')).strip()
            password = str(data.get('password', ''))

            if not all([username, email, first_name, last_name, password]):
                missing_fields = [field for field, value in {
                    'username': username,
                    'email': email,
                    'firstName': first_name,
                    'lastName': last_name,
                    'password': password
                }.items() if not value]
                
                return jsonify({
                    'status': 'error',
                    'message': f'Missing required fields: {", ".join(missing_fields)}'
                }), 400

            setup_aws_credentials()
            client = boto3.client('cognito-idp', region_name=AWS_REGION)
            
            try:
                response = client.sign_up(
                    ClientId=CLIENT_ID,
                    SecretHash=get_secret_hash(username),
                    Username=username,
                    Password=password,
                    UserAttributes=[
                        {
                            'Name': 'email',
                            'Value': email
                        },
                        {
                            'Name': 'given_name',
                            'Value': first_name
                        },
                        {
                            'Name': 'family_name',
                            'Value': last_name
                        }
                    ]
                )
                
                # Store password temporarily for auto-login after confirmation
                session['temp_password'] = password
                
                # Create local user record
                user = User(username=username, password='[COGNITO_MANAGED]')
                db.session.add(user)
                db.session.commit()
                
                app.logger.info(f'Successfully registered user: {username}')
                return jsonify({
                    'status': 'success',
                    'message': 'Registration successful! Please check your email for verification code.',
                    'user_sub': response['UserSub']
                })
                
            except ClientError as e:
                error_message = str(e)
                app.logger.error(f'AWS Cognito error for user {username}: {error_message}')
                
                if 'UsernameExistsException' in error_message:
                    message = "Username already exists"
                elif 'InvalidPasswordException' in error_message:
                    message = "Invalid password format"
                else:
                    message = "Registration failed, please try again later"
                return jsonify({'status': 'error', 'message': message}), 400
                
        except Exception as e:
            app.logger.error(f'Unexpected error during registration: {str(e)}')
            return jsonify({
                'status': 'error',
                'message': 'An unexpected error occurred'
            }), 500
            
    return render_template('register.html')

@app.route('/confirm-signup', methods=['POST'])
def confirm_signup():
    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({
                    'status': 'error',
                    'message': 'No JSON data received'
                }), 400

            username = str(data.get('username', '')).strip()
            confirmation_code = str(data.get('code', '')).strip()

            app.logger.info(f'Confirming signup for user: {username}')
            app.logger.debug(f'Confirmation code length: {len(confirmation_code)}')

            if not username or not confirmation_code:
                return jsonify({
                    'status': 'error',
                    'message': 'Username and verification code are required'
                }), 400

            try:
                client = setup_aws_credentials()
                
                secret_hash = get_secret_hash(username)
                
                app.logger.debug('Attempting to confirm sign up with AWS Cognito')
                
                response = client.confirm_sign_up(
                    ClientId=CLIENT_ID,
                    SecretHash=secret_hash,
                    Username=username,
                    ConfirmationCode=confirmation_code
                )
                
                app.logger.info(f'Successfully confirmed signup for user: {username}')
                app.logger.debug(f'Cognito response: {response}')
                
                try:
                    temp_password = session.get('temp_password')
                    if not temp_password:
                        app.logger.warning('No temporary password found in session')
                        return jsonify({
                            'status': 'success',
                            'message': 'Email verified successfully! Please login.'
                        })

                    auth_response = client.initiate_auth(
                        ClientId=CLIENT_ID,
                        AuthFlow='USER_PASSWORD_AUTH',
                        AuthParameters={
                            'USERNAME': username,
                            'PASSWORD': temp_password,
                            'SECRET_HASH': secret_hash
                        }
                    )
                    
                    user = User.query.filter_by(username=username).first()
                    if not user:
                        user = User(username=username, password='[COGNITO_MANAGED]')
                        db.session.add(user)
                        db.session.commit()
                    
                    login_user(user)
                    
                    session.pop('temp_password', None)
                    
                    return jsonify({
                        'status': 'success',
                        'message': 'Email verified and logged in successfully!',
                        'tokens': {
                            'access_token': auth_response['AuthenticationResult']['AccessToken'],
                            'id_token': auth_response['AuthenticationResult']['IdToken'],
                            'refresh_token': auth_response['AuthenticationResult']['RefreshToken']
                        }
                    })
                    
                except ClientError as e:
                    app.logger.error(f'Auto-login failed for user {username}: {str(e)}')
                    return jsonify({
                        'status': 'success',
                        'message': 'Email verified successfully! Please login.'
                    })
                
            except ClientError as e:
                error_message = str(e)
                app.logger.error(f'AWS Cognito error during confirmation for user {username}: {error_message}')
                
                if 'CodeMismatchException' in error_message:
                    message = "Invalid verification code"
                elif 'ExpiredCodeException' in error_message:
                    message = "Verification code has expired"
                elif 'NotAuthorizedException' in error_message:
                    message = "Unable to verify email. Please try again"
                else:
                    message = f"Verification failed: {error_message}"
                return jsonify({'status': 'error', 'message': message}), 400
                
        except Exception as e:
            app.logger.error(f'Unexpected error during confirmation: {str(e)}')
            return jsonify({
                'status': 'error',
                'message': f'An unexpected error occurred: {str(e)}'
            }), 500
            
    return jsonify({'status': 'error', 'message': 'Invalid request'}), 400

@app.route('/api/get-upload-url', methods=['GET'])
@login_required
def get_upload_url_proxy():
    try:
        id_token = session.get('id_token')
        if not id_token:
            app.logger.error("No ID token found in session")
            return jsonify({'error': 'No authentication token found'}), 401

        app.logger.info("Requesting upload URL from API...")
        
        headers = {
            'Authorization': f"Bearer {id_token}"
        }
        
        app.logger.debug(f"Request headers: {headers}")
        
        API_BASE_URL = "https://pzsjhrvhz8.execute-api.us-east-1.amazonaws.com/dev"
        response = requests.get(
            f"{API_BASE_URL}/get-upload-url",
            headers=headers,
            timeout=10
        )

        app.logger.info(f"API Response Status: {response.status_code}")
        app.logger.debug(f"API Response Headers: {dict(response.headers)}")
        app.logger.debug(f"API Response Body: {response.text}")

        if response.status_code == 200:
            upload_info = response.json()
            app.logger.info(f"Successfully got upload URL. S3 Key: {upload_info.get('s3_key')}")
            return jsonify(upload_info), 200
        else:
            app.logger.error(f"API request failed with status {response.status_code}: {response.text}")
            return jsonify({
                'error': f"Failed to get upload URL: {response.status_code} {response.reason}"
            }), response.status_code

    except requests.RequestException as e:
        app.logger.error(f"Request error: {str(e)}")
        return jsonify({'error': f'Failed to get upload URL: {str(e)}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload-to-s3', methods=['POST'])
@login_required
def upload_to_s3_proxy():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file:
            return jsonify({'error': 'Empty file provided'}), 400

        id_token = session.get('id_token')
        if not id_token:
            return jsonify({'error': 'No authentication token found'}), 401

        # 获取上传URL
        API_BASE_URL = "https://pzsjhrvhz8.execute-api.us-east-1.amazonaws.com/dev"
        headers = {'Authorization': f"Bearer {id_token}"}
        response = requests.get(f"{API_BASE_URL}/get-upload-url", headers=headers)
        
        if not response.ok:
            return jsonify({'error': 'Failed to get upload URL'}), response.status_code
        
        upload_info = response.json()
        upload_url = upload_info['upload_url']
        s3_key = upload_info['s3_key']

        # 上传文件到S3
        upload_response = requests.put(
            upload_url,
            data=file.stream.read(),
            headers={'Content-Type': file.content_type}
        )

        if upload_response.ok:
            return jsonify({
                'status': 'success',
                'message': 'File uploaded successfully',
                's3_key': s3_key
            })
        else:
            return jsonify({
                'error': f'Failed to upload to S3: {upload_response.status_code} {upload_response.reason}'
            }), upload_response.status_code

    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/api/proxy-image')
@login_required
def proxy_image():
    try:
        url = request.args.get('url')
        if not url:
            return "图片URL未提供", 400
            
        # 验证URL是否来自我们的S3存储桶
        if not url.startswith('https://pixtag-thumbnail666.s3.amazonaws.com/'):
            return "非法的图片URL", 403

        # 设置AWS凭证
        s3_client = boto3.client('s3')
        
        # 从URL中提取存储桶名称和键
        parsed_url = urlparse(url)
        bucket = parsed_url.netloc.split('.')[0]
        key = parsed_url.path.lstrip('/')
        
        try:
            # 获取S3对象
            response = s3_client.get_object(Bucket=bucket, Key=key)
            image_data = response['Body'].read()
            
            # 确定内容类型
            content_type = response.get('ContentType', 'image/jpeg')
            
            # 返回图片数据
            return Response(
                image_data,
                content_type=content_type,
                headers={
                    'Cache-Control': 'public, max-age=31536000',
                    'Access-Control-Allow-Origin': '*'
                }
            )
            
        except s3_client.exceptions.NoSuchKey:
            return "图片不存在", 404
        except Exception as e:
            app.logger.error(f"获取S3图片失败: {str(e)}")
            return "获取图片失败", 500
            
    except Exception as e:
        app.logger.error(f"代理图片请求失败: {str(e)}")
        return "处理请求失败", 500

@app.route('/api/search-by-tags', methods=['POST'])
@login_required
def search_by_tags():
    try:
        if not session.get('id_token'):
            return jsonify({'error': '认证已过期，请重新登录'}), 401

        data = request.get_json()
        if not data or 'tags' not in data:
            return jsonify({'error': '未提供标签'}), 400

        tags = data.get('tags', [])
        app.logger.info(f"搜索标签: {tags}")

        url = f"{API_BASE_URL}/search-by-tags"
        headers = {
            'Authorization': f"Bearer {session['id_token']}",
            'Content-Type': 'application/json'
        }
        
        app.logger.debug(f"请求头: {headers}")
        
        try:
            response = requests.post(
                url,
                headers=headers,
                json={'tags': tags},
                timeout=10
            )

            app.logger.info(f"API响应状态: {response.status_code}")
            app.logger.debug(f"API响应内容: {response.text}")

            if response.status_code == 200:
                result = response.json()
                if isinstance(result, dict) and 'body' in result:
                    try:
                        body = json.loads(result['body']) if isinstance(result['body'], str) else result['body']
                        app.logger.info(f"找到 {len(body.get('links', []))} 张图片")
                        return jsonify(body), 200
                    except json.JSONDecodeError:
                        app.logger.error("解析Lambda响应body失败")
                        return jsonify({'error': '响应格式不正确'}), 500
                else:
                    app.logger.info(f"找到 {len(result.get('links', []))} 张图片")
                    return jsonify(result), 200
            elif response.status_code == 403:
                # 令牌过期，尝试刷新
                if refresh_auth_token():
                    # 重试请求
                    headers['Authorization'] = f"Bearer {session['id_token']}"
                    response = requests.post(
                        url,
                        headers=headers,
                        json={'tags': tags},
                        timeout=10
                    )
                    if response.status_code == 200:
                        result = response.json()
                        if isinstance(result, dict) and 'body' in result:
                            body = json.loads(result['body']) if isinstance(result['body'], str) else result['body']
                            app.logger.info(f"令牌刷新后找到 {len(body.get('links', []))} 张图片")
                            return jsonify(body), 200
                return jsonify({'error': '认证已过期，请重新登录'}), 401
            else:
                error_message = response.text
                app.logger.error(f"API请求失败，状态码 {response.status_code}: {error_message}")
                return jsonify({
                    'error': f"搜索失败: {response.status_code} {response.reason}",
                    'details': error_message
                }), response.status_code

        except requests.RequestException as e:
            app.logger.error(f"请求错误: {str(e)}")
            return jsonify({'error': f'搜索请求失败: {str(e)}'}), 500

    except Exception as e:
        app.logger.error(f"意外错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/subscription')
@login_required
def subscription():
    if not session.get('id_token'):
        flash('请先登录')
        return redirect(url_for('login'))
    return render_template('subscription.html')

@app.route('/api/list-topics', methods=['POST'])
@login_required
def list_topics():
    try:
        if not session.get('id_token'):
            return jsonify({'error': '认证已过期，请重新登录'}), 401

        url = "https://cabj3djyl2.execute-api.us-east-1.amazonaws.com/dev/list_topics_with_images_lambda"
        headers = {
            'Authorization': f"Bearer {session['id_token']}",
            'Content-Type': 'application/json'
        }
        
        app.logger.info("正在获取可用的标签列表...")
        response = requests.post(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            topics = response.json()
            app.logger.info(f"成功获取到 {len(topics)} 个标签")
            return jsonify(topics)
        elif response.status_code == 403:
            # 令牌过期，尝试刷新
            if refresh_auth_token():
                # 重试请求
                headers['Authorization'] = f"Bearer {session['id_token']}"
                response = requests.post(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    topics = response.json()
                    app.logger.info(f"令牌刷新后成功获取到 {len(topics)} 个标签")
                    return jsonify(topics)
            return jsonify({'error': '认证已过期，请重新登录'}), 401
        else:
            app.logger.error(f"获取标签列表失败: {response.status_code} - {response.text}")
            return jsonify({'error': '获取标签列表失败'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"获取标签列表时发生错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/subscribe', methods=['POST'])
@login_required
def subscribe():
    try:
        if not session.get('id_token'):
            return jsonify({'error': '认证已过期，请重新登录'}), 401

        data = request.get_json()
        if not data or 'email' not in data or 'tags' not in data:
            return jsonify({'error': '缺少必要的参数'}), 400
            
        email = data['email']
        tags = data['tags']
        
        if not email or not tags:
            return jsonify({'error': '邮箱和标签不能为空'}), 400
            
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            return jsonify({'error': '标签格式不正确'}), 400
            
        url = "https://g33sycieq6.execute-api.us-east-1.amazonaws.com/dev/subscribe_tag"
        headers = {
            'Authorization': f"Bearer {session['id_token']}",
            'Content-Type': 'application/json'
        }
        
        app.logger.info(f"正在为邮箱 {email} 订阅标签: {tags}")
        response = requests.post(url, headers=headers, json=data, timeout=10)
        
        if response.status_code == 200:
            app.logger.info("订阅成功")
            return jsonify(response.json())
        elif response.status_code == 403:
            # 令牌过期，尝试刷新
            if refresh_auth_token():
                # 重试请求
                headers['Authorization'] = f"Bearer {session['id_token']}"
                response = requests.post(url, headers=headers, json=data, timeout=10)
                if response.status_code == 200:
                    app.logger.info("令牌刷新后订阅成功")
                    return jsonify(response.json())
            return jsonify({'error': '认证已过期，请重新登录'}), 401
        else:
            app.logger.error(f"订阅失败: {response.status_code} - {response.text}")
            return jsonify({'error': '订阅失败'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"处理订阅请求时发生错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

def refresh_auth_token():
    """刷新认证令牌"""
    try:
        if not session.get('refresh_token'):
            return False

        client = boto3.client('cognito-idp', region_name=AWS_REGION)
        auth_response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': session['refresh_token'],
                'SECRET_HASH': get_secret_hash(session.get('username', ''))
            }
        )
        
        if 'AuthenticationResult' in auth_response:
            session['access_token'] = auth_response['AuthenticationResult']['AccessToken']
            session['id_token'] = auth_response['AuthenticationResult']['IdToken']
            return True
            
    except Exception as e:
        app.logger.error(f"刷新令牌失败: {str(e)}")
        
    return False

@app.route('/api/search-by-time', methods=['POST'])
@login_required
def search_by_time():
    try:
        if not session.get('id_token'):
            return jsonify({'error': '认证已过期，请重新登录'}), 401

        data = request.get_json()
        if not data or 'start_time' not in data or 'end_time' not in data:
            return jsonify({'error': '未提供开始时间或结束时间'}), 400

        start_time = data.get('start_time')
        end_time = data.get('end_time')
        
        if not isinstance(start_time, int) or not isinstance(end_time, int):
            return jsonify({'error': '时间必须是整数'}), 400
            
        if start_time >= end_time:
            return jsonify({'error': '开始时间必须小于结束时间'}), 400

        app.logger.info(f"按时间搜索: {start_time} 到 {end_time}")
        
        url = "https://hvffd89txl.execute-api.us-east-1.amazonaws.com/dev/SearchByTimeLambda"
        headers = {
            'Authorization': f"Bearer {session['id_token']}",
            'Content-Type': 'application/json'
        }
        
        app.logger.debug(f"请求头: {headers}")
        
        try:
            response = requests.post(
                url,
                headers=headers,
                json={
                    'start_time': start_time,
                    'end_time': end_time
                },
                timeout=10
            )

            app.logger.info(f"API响应状态: {response.status_code}")
            app.logger.debug(f"API响应内容: {response.text}")

            if response.status_code == 200:
                result = response.json()
                if isinstance(result, dict) and 'body' in result:
                    try:
                        body = json.loads(result['body']) if isinstance(result['body'], str) else result['body']
                        app.logger.info(f"找到 {len(body.get('results', []))} 条记录")
                        return jsonify(body), 200
                    except json.JSONDecodeError:
                        app.logger.error("解析Lambda响应body失败")
                        return jsonify({'error': '响应格式不正确'}), 500
                else:
                    app.logger.info(f"找到 {len(result.get('results', []))} 条记录")
                    return jsonify(result), 200
            elif response.status_code == 403:
                # 令牌过期，尝试刷新
                if refresh_auth_token():
                    # 重试请求
                    headers['Authorization'] = f"Bearer {session['id_token']}"
                    response = requests.post(
                        url,
                        headers=headers,
                        json={
                            'start_time': start_time,
                            'end_time': end_time
                        },
                        timeout=10
                    )
                    if response.status_code == 200:
                        result = response.json()
                        if isinstance(result, dict) and 'body' in result:
                            body = json.loads(result['body']) if isinstance(result['body'], str) else result['body']
                            app.logger.info(f"令牌刷新后找到 {len(body.get('results', []))} 条记录")
                            return jsonify(body), 200
                return jsonify({'error': '认证已过期，请重新登录'}), 401
            else:
                error_message = response.text
                app.logger.error(f"API请求失败，状态码 {response.status_code}: {error_message}")
                return jsonify({
                    'error': f"搜索失败: {response.status_code} {response.reason}",
                    'details': error_message
                }), response.status_code

        except requests.RequestException as e:
            app.logger.error(f"请求错误: {str(e)}")
            return jsonify({'error': f'搜索请求失败: {str(e)}'}), 500

    except Exception as e:
        app.logger.error(f"意外错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-image', methods=['POST'])
@login_required
def delete_image():
    try:
        if not session.get('id_token'):
            return jsonify({'error': '认证已过期，请重新登录'}), 401

        data = request.get_json()
        if not data or 'image_id' not in data:
            return jsonify({'error': '未提供图片ID'}), 400

        image_id = data.get('image_id')
        
        app.logger.info(f"删除图片: {image_id}")
        
        url = "https://wthhbyow7d.execute-api.us-east-1.amazonaws.com/dev/image"
        headers = {
            'Authorization': f"Bearer {session['id_token']}",
            'Content-Type': 'application/json'
        }
        
        app.logger.debug(f"请求头: {headers}")
        
        response = requests.post(
            url,
            headers=headers,
            json={'image_id': image_id},
            timeout=10
        )

        app.logger.info(f"API响应状态: {response.status_code}")
        app.logger.debug(f"API响应内容: {response.text}")

        if response.status_code == 200:
            result = response.json()
            return jsonify(result), 200
        elif response.status_code == 403:
            # 令牌过期，尝试刷新
            if refresh_auth_token():
                headers['Authorization'] = f"Bearer {session['id_token']}"
                response = requests.post(
                    url,
                    headers=headers,
                    json={'image_id': image_id},
                    timeout=10
                )
                if response.status_code == 200:
                    result = response.json()
                    return jsonify(result), 200
            return jsonify({'error': '认证已过期，请重新登录'}), 401
        else:
            error_message = response.text
            app.logger.error(f"API请求失败，状态码 {response.status_code}: {error_message}")
            return jsonify({
                'error': f"删除失败: {response.status_code} {response.reason}",
                'details': error_message
            }), response.status_code

    except requests.RequestException as e:
        app.logger.error(f"请求错误: {str(e)}")
        return jsonify({'error': f'删除请求失败: {str(e)}'}), 500
    except Exception as e:
        app.logger.error(f"意外错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/management')
@login_required
def management():
    return render_template('management.html')

@app.route('/api/get-all-images', methods=['GET'])
@login_required
def get_all_images():
    try:
        if not session.get('id_token'):
            return jsonify({'error': '认证已过期，请重新登录'}), 401

        url = "https://v1w66xnsq0.execute-api.us-east-1.amazonaws.com/dev/DeleteAll"
        headers = {
            'Authorization': f"Bearer {session['id_token']}",
            'Content-Type': 'application/json'
        }
        
        app.logger.debug(f"请求头: {headers}")
        
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        app.logger.info(f"API响应状态: {response.status_code}")
        app.logger.debug(f"API响应内容: {response.text}")

        if response.status_code == 200:
            result = response.json()
            return jsonify(result), 200
        elif response.status_code == 403:
            if refresh_auth_token():
                headers['Authorization'] = f"Bearer {session['id_token']}"
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    result = response.json()
                    return jsonify(result), 200
            return jsonify({'error': '认证已过期，请重新登录'}), 401
        else:
            error_message = response.text
            app.logger.error(f"API请求失败，状态码 {response.status_code}: {error_message}")
            return jsonify({
                'error': f"获取图片失败: {response.status_code} {response.reason}",
                'details': error_message
            }), response.status_code

    except requests.RequestException as e:
        app.logger.error(f"请求错误: {str(e)}")
        return jsonify({'error': f'获取图片请求失败: {str(e)}'}), 500
    except Exception as e:
        app.logger.error(f"意外错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True) 