from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response

from storage.db import *

@api_view(['POST'])
def analyse_url_view(request):

    if request.method == 'POST':
        url = request.data.get('url', None)

    if not url:
        return Response({'error: URL não foi fornecida'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        normalize_url = extract_hostname(url)

        analysis_id = insert_analysis(url, normalize_url)

        """---falta colocar a funcao que faz as heuristicas---"""

        """heuristicas = get_heuristics_hits(analysis_id)"""

        """---falta a funcao que faz a reputacao---"""

        """reputacoes = get_reputation_checks(analysis_id)"""

        """---falta a funcao que chama a XAI---"""

        """xai = get_ai_requests(analysis_id)"""

        """Para questao de teste, recebe apenas o id da analise por agora"""
        return Response(analysis_id, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

