import json
import boto3
from boto3.dynamodb.conditions import Attr
from collections import defaultdict
from typing import List, Dict, Set, Any

# 初始化 DynamoDB 资源
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('PixTag-Metadata')

def validate_input(event: Dict[str, Any]) -> List[str]:
    """
    验证并处理 Lambda 函数的输入参数
    
    @param {Dict[str, Any]} event - Lambda 事件对象
    @returns {List[str]} - 经过去重的标签列表
    @throws {ValueError} - 当输入验证失败时抛出
    """
    if not isinstance(event, dict):
        raise ValueError("事件对象必须是字典类型")
        
    if 'body' not in event:
        raise ValueError("请求缺少 body")
    
    try:
        body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
    except json.JSONDecodeError:
        raise ValueError("请求体不是合法 JSON")
    
    if not isinstance(body, dict):
        raise ValueError("请求体必须是对象类型")
        
    tags = body.get('tags')
    if not isinstance(tags, list) or not tags:
        raise ValueError("tags 字段必须是非空列表")
        
    # 验证每个标签是否为字符串类型
    if not all(isinstance(tag, str) for tag in tags):
        raise ValueError("所有标签必须是字符串类型")
        
    # 去除空字符串并去重
    valid_tags = [tag.strip() for tag in tags if tag.strip()]
    if not valid_tags:
        raise ValueError("标签列表不能全为空")
        
    return list(set(valid_tags))

def query_all_tags(tags: List[str]) -> List[Dict[str, Any]]:
    """
    扫描 DynamoDB 表查找包含指定标签的所有记录
    
    @param {List[str]} tags - 要查询的标签列表
    @returns {List[Dict[str, Any]]} - 查询结果列表
    """
    print(f"扫描数据库中标签属于 {tags} 的记录...")
    filter_expr = Attr('tag').is_in(tags)
    results = []
    
    try:
        response = table.scan(FilterExpression=filter_expr)
        results.extend(response['Items'])
        
        while 'LastEvaluatedKey' in response:
            response = table.scan(
                FilterExpression=filter_expr,
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            results.extend(response['Items'])
    except Exception as e:
        print(f"DynamoDB 查询错误: {str(e)}")
        raise
        
    return results

def aggregate_by_image(items: List[Dict[str, Any]], required_tags: List[str]) -> List[str]:
    """
    聚合查询结果，返回同时包含所有必需标签的图片缩略图URL列表
    
    @param {List[Dict[str, Any]]} items - DynamoDB 查询结果
    @param {List[str]} required_tags - 必需的标签列表
    @returns {List[str]} - 匹配的缩略图URL列表
    """
    image_tags: Dict[str, Set[str]] = defaultdict(set)
    image_thumbnails: Dict[str, str] = {}
    
    for item in items:
        img_id = item.get('image_id')
        tag = item.get('tag')
        
        if not img_id or not tag:
            continue
            
        image_tags[img_id].add(tag)
        
        if img_id not in image_thumbnails:
            thumbnail_url = item.get('thumbnail_url', '')
            if thumbnail_url:  # 只保存非空的缩略图URL
                image_thumbnails[img_id] = thumbnail_url
    
    required_tagset = set(required_tags)
    matched_thumbs = [
        url for img_id, url in image_thumbnails.items()
        if required_tagset.issubset(image_tags[img_id])
    ]
    
    return matched_thumbs

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda 函数入口点
    
    @param {Dict[str, Any]} event - Lambda 事件对象
    @param {Any} context - Lambda 上下文对象
    @returns {Dict[str, Any]} - API Gateway 响应对象
    """
    try:
        tags = validate_input(event)
        items = query_all_tags(tags)
        thumbnails = aggregate_by_image(items, tags)
        
        response_body = {
            "links": thumbnails,
            "count": len(thumbnails)
        }
        
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps(response_body)
        }
        
    except ValueError as ve:
        error_response = {
            "error": str(ve),
            "error_type": "ValidationError"
        }
        return {
            "statusCode": 400,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps(error_response)
        }
        
    except Exception as e:
        print(f"服务器内部错误: {str(e)}")
        error_response = {
            "error": "服务器内部错误",
            "error_type": "InternalError"
        }
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps(error_response)
        } 